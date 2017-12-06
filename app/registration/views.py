from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import ProfileForm
from urllib import parse
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
import furl
import jwt
import base64
import json

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

            return render(request, template_name, {'form': form})
    else:
        registration, created = Registration.objects.get_or_create(user_id=user.id)

        # This should be handled as read only pre-popluated.
        registration.email = user.username

        # If this is a new user registration, save so that we capture the e-mail.
        if created:
            registration.save()

        form = ProfileForm(instance=registration)

    return render(request, template_name, {'form': form, 'user': user})


@user_auth_and_jwt
def access(request, template_name='registration/access.html'):
    return render(request, template_name)


@user_auth_and_jwt
def email_confirm(request, template_name='registration/confirmed.html'):
    user = request.user

    success_url = None
    try:
        # Get the email confirm data.
        email_confirm_value = base64.urlsafe_b64decode(request.GET.get('email_confirm_value', '---').encode('utf-8')).decode('utf-8')
        email_confirm_value = user.email + ":" + email_confirm_value.replace(".", ":")

        # Get the success url.
        success_url = base64.urlsafe_b64decode(request.GET.get('success_url').encode('utf-8')).decode('utf-8')

        # Verify the code.
        signer = TimestampSigner(salt=settings.EMAIL_CONFIRM_SALT)
        signer.unsign(email_confirm_value, max_age=timedelta(seconds=300))
        registration, created = Registration.objects.get_or_create(user_id=user.id)

        # If this is a new registration make sure we at least save the email/username.
        if created:
            registration.email = user.username

        registration.email_confirmed = True
        registration.save()

        # Set a message.
        messages.success(request, 'Email has been confirmed.',
                         extra_tags='success', fail_silently=True)

        # Continue on to the next page, if passed. Otherwise render a default page.
        if success_url:
            return redirect(success_url)

    except SignatureExpired as e:
        logger.exception('[SciReg][registration.views.email_confirm] Exception: ' + str(e))
        messages.error(request, 'This email confirmation code has expired, please try again.',
                       extra_tags='danger', fail_silently=True)

    except Exception as e:
        logger.exception('[SciReg][registration.views.email_confirm] Exception: ' + str(e))
        messages.error(request, 'This email confirmation code is invalid, please try again.',
                       extra_tags='danger', fail_silently=True)

    # Send them to a default URL
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

        # Store the data to be passed for verification.
        email_confirm_dict = {}

        # Build the email verification code and b64 encode it.
        signer = TimestampSigner(salt=settings.EMAIL_CONFIRM_SALT)
        signed_value = signer.sign(user.email)
        signed_value = signed_value.split(":")[1] + "." + signed_value.split(":")[2]

        email_confirm_dict['email_confirm_value'] = base64.urlsafe_b64encode(bytes(signed_value, 'utf-8')).decode('utf-8')

        # Check for a success url and b64 encode it.
        success_url = request.data.get('success_url')
        if success_url:
            email_confirm_dict['success_url'] = base64.urlsafe_b64encode(bytes(success_url, 'utf-8')).decode('utf-8')

        # Build the URL.
        confirm_url = furl.furl(settings.CONFIRM_EMAIL_URL)

        # Add the parameters.
        confirm_url.args.update(email_confirm_dict)

        logger.debug("[SCIREG][DEBUG][send_confirmation_email] Assembled confirmation URL: %s" % confirm_url.url)

        email_send("People-Powered Medicine - E-Mail Verification", [user.email],
                   message="verify",
                   extra={"confirm_url": confirm_url.url, "user_email": user.email})

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

