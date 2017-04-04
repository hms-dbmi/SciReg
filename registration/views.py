from django.shortcuts import render, redirect
from .forms import ProfileForm
from registration.models import Registration
from rest_framework import viewsets, permissions
from rest_framework.decorators import list_route
from registration.serializers import RegistrationSerializer, UserSerializer
from registration.permissions import IsAssociatedUser
from rest_framework.permissions import AllowAny
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from django.core.signing import TimestampSigner, SignatureExpired, BadSignature
from datetime import timedelta
from django.http import HttpResponse
from django.contrib.auth.models import User
from SciReg.auth0authenticate import user_auth_and_jwt


import jwt
import base64

import logging
logger = logging.getLogger(__name__)

@user_auth_and_jwt
def profile(request, template_name='registration/profile.html'):
    user = request.user

    logger.info("[SCIREG][DEBUG][profile] - Rendering user profile for user " + str(user.id))

    if request.method == 'POST':

        form = ProfileForm(request.POST)

        if form.is_valid():
            # User should always have a registration at this point.
            registration = Registration.objects.get(user_id=user.id)

            # Extract data from form into registration object.
            registration.affiliation = form.cleaned_data['affiliation']
            registration.affiliation_type = form.cleaned_data['affiliation_type']
            registration.data_interest = form.cleaned_data['data_interest']
            registration.software_interest = form.cleaned_data['software_interest']
            registration.technical_consult_interest = form.cleaned_data['technical_consult_interest']
            registration.save()

            return render(request, template_name, {'form': form, 'jwt': request.COOKIES.get("DBMI_JWT", None)})
    else:
        registration, created = Registration.objects.get_or_create(user_id=user.id)

        # This should be handled as read only pre-popluated.
        registration.email = user.username

        # If this is a new user registration, save so that we capture the e-mail.
        if created:
            registration.save()

        form = ProfileForm(instance=registration)

    return render(request, template_name, {'form': form, 'user': user, 'jwt': request.COOKIES.get("DBMI_JWT", None)})


@user_auth_and_jwt
def access(request, template_name='registration/access.html'):
    return render(request, template_name)


@user_auth_and_jwt
def email_confirm(request, template_name='registration/confirmed.html'):
    user = request.user

    email_confirm_value = request.GET['email_confirm_value']
    email_confirm_value = user.email + ":" + email_confirm_value.replace(".", ":")
    signer = TimestampSigner(salt=EMAIL_CONFIRM_SALT)

    try:
        signer.unsign(email_confirm_value, max_age=timedelta(seconds=300))
        registration, created = Registration.objects.get_or_create(user_id=user.id)
        registration.email_confirmed = True
        registration.save()
    except SignatureExpired:
        return HttpResponse("SIGNATURE EXPIRED")
    except BadSignature:
        return HttpResponse("BAD SIGNATURE")
    return render(request, template_name)


class RegistrationViewSet(viewsets.ModelViewSet):
    queryset = Registration.objects.all()
    serializer_class = RegistrationSerializer
    permission_classes = (permissions.IsAuthenticated, IsAssociatedUser,)

    def perform_create(self, serializer):
        user = self.request.user

        if Registration.objects.filter(email=user.email).exists():
            return Registration.objects.filter(email=user.email)
        else:
            serializer.save(user=user, email=user.email)

    def get_queryset(self):
        user = self.request.user
        return Registration.objects.filter(user=user)

    @list_route(methods=['post'])
    def send_confirmation_email(self, request):
        user = request.user

        signer = TimestampSigner(salt=settings.EMAIL_CONFIRM_SALT)
        signed_value = signer.sign(user.email)

        signed_value = signed_value.split(":")[1] + "." + signed_value.split(":")[2]

        email_send("User account creation confirmation", [user.email], message="verify", extra={"signed_value": signed_value, "confirm_url": settings.CONFIRM_EMAIL_URL})

        return HttpResponse("SENT")


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (AllowAny,)

    def perform_create(self, serializer):

        jwt_string = self.request.POST['JWT']

        try:
            payload = jwt.decode(jwt_string, base64.b64decode(settings.AUTH0_SECRET, '-_'), algorithms=['HS256'], audience=settings.AUTH0_CLIENT_ID)
        except jwt.InvalidTokenError:
            print("No/Bad JWT Token.")

        if User.objects.filter(email=payload['email']).exists():
            return User.objects.filter(email=payload['email'])
        else:
            user = User(username=payload['email'], email=payload['email'])
            user.set_unusable_password()
            user.save()
            return user


def email_send(subject=None, recipients=None, message=None, extra=None):

    for r in recipients:

        msg_html = render_to_string('email/%s.html' % message, extra)
        msg_plain = render_to_string('email/%s.txt' % message, extra)

        print("About to send mail %s" % r)

        if settings.DEBUG and False:
            print(msg_html)
        else:
            print(msg_html)
            send_mail(subject=subject, message=msg_html, from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[r])

        print("Email success: %s to %s" % (subject, r))

