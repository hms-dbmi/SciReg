from django.shortcuts import render
from .forms import ProfileForm
from registration.models import Registration
from rest_framework import viewsets, permissions
from rest_framework.decorators import list_route
from registration.serializers import RegistrationSerializer, UserSerializer
from registration.permissions import IsAssociatedUser
from rest_framework.permissions import AllowAny
from django.template.loader import render_to_string
from django.conf import settings
from django.core.signing import TimestampSigner, SignatureExpired, BadSignature
from datetime import timedelta
from django.http import HttpResponse
from django.contrib.auth.models import User
from pyauth0jwt.auth0authenticate import user_auth_and_jwt
from django.core.mail import EmailMultiAlternatives
from socket import gaierror
import sys

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

    signer = TimestampSigner(salt=settings.EMAIL_CONFIRM_SALT)

    try:
        signer.unsign(email_confirm_value, max_age=timedelta(seconds=300))
        registration, created = Registration.objects.get_or_create(user_id=user.id)

        # If this is a new registration make sure we at least save the email/username.
        if created:
            registration.email = user.username

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

        email_send("Harvard Medical School - E-Mail Verification", [user.email], message="verify", extra={"signed_value": signed_value,
                                                                                                          "confirm_url": settings.CONFIRM_EMAIL_URL,
                                                                                                          "user_email": user.email})

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
    """
    Send an e-mail to a list of participants with the given subject and message. 
    Extra is dictionary of variables to be swapped into the template.
    """
    for r in recipients:
        msg_html = render_to_string('email/%s.html' % message, extra)
        msg_plain = render_to_string('email/%s.txt' % message, extra)

        logger.info("[SCIREG][DEBUG][email_send] About to send e-mail to %s" % r)

        try:
            msg = EmailMultiAlternatives(subject, msg_plain, settings.DEFAULT_FROM_EMAIL, [r])
            msg.attach_alternative(msg_html, "text/html")
            msg.send()
        except gaierror:
            logger.error("[SCIREG][DEBUG][email_send] Could not send mail! Possible bad server connection.")
        except:
            print(sys.exc_info()[0])

        logger.info("[SCIREG][DEBUG][email_send] E-Mail Success!")

