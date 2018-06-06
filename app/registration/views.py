import sys
import furl
import jwt
import base64
import json
import requests

from datetime import timedelta
from functools import reduce
from operator import or_
from os.path import normpath, join, dirname, abspath
from socket import gaierror
from urllib import parse

from rest_framework import status
from rest_framework import permissions
from rest_framework import viewsets
from rest_framework.decorators import list_route
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from registration.serializers import RegistrationSerializer
from registration.serializers import UserSerializer
from registration.permissions import IsAssociatedUser

from pyauth0jwt.auth0authenticate import user_auth_and_jwt

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import EmailMultiAlternatives
from django.core.serializers.json import DjangoJSONEncoder
from django.core.signing import TimestampSigner
from django.core.signing import SignatureExpired
from django.core.signing import BadSignature
from django.db.models import Count
from django.db.models import Q
from django.http import HttpResponse
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.shortcuts import redirect
from django.template.loader import render_to_string

from SciReg import sciauthz_services
from registration.forms import ProfileForm
from registration.models import Registration

import logging
logger = logging.getLogger(__name__)


@user_auth_and_jwt
def profile(request, template_name='registration/profile.html'):
    logger.debug("Profile - {}".format(request.method))
    user = request.user

    if request.method == 'POST':

        form = ProfileForm(request.POST)

        if form.is_valid():
            logger.debug("Profile form is valid")

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
        logger.debug("Checking for user's profile")
        registration, created = Registration.objects.get_or_create(user_id=user.id)

        # This should be handled as read only pre-popluated.
        registration.email = user.username

        # If this is a new user registration, save so that we capture the e-mail.
        if created:
            logger.debug("Creating profile for user")
            registration.save()
        else:
            logger.debug("Found profile for user")

        form = ProfileForm(instance=registration)

    return render(request, template_name, {'form': form, 'user': user})


@user_auth_and_jwt
def access(request, template_name='registration/access.html'):
    return render(request, template_name)


@user_auth_and_jwt
def email_confirm(request, template_name='registration/confirmed.html'):
    logger.debug("Email Confirm: {}".format(request.GET))
    user = request.user

    success_url = None
    state = {'task': 'email_confirm'}
    try:
        # Get the email confirm data
        email_confirm_json = base64.urlsafe_b64decode(request.GET.get('email_confirm_value').encode('utf-8')).decode('utf-8')
        email_confirm_dict = json.loads(email_confirm_json)

        logger.debug('Email confirmation data: {}'.format(email_confirm_json))

        # Get the success url.
        success_url = email_confirm_dict.get('success_url')

        logger.debug('Email confirmation success URL: {}'.format(success_url))

        # Get the email confirm data.
        email_confirm_value = email_confirm_dict.get('email_confirm_value', '---')
        email_confirm_value = user.email + ":" + email_confirm_value.replace(".", ":")
        logger.debug("Email Confirm value: {}".format(email_confirm_value))

        # Verify the code.
        signer = TimestampSigner(salt=settings.EMAIL_CONFIRM_SALT)
        signer.unsign(email_confirm_value, max_age=timedelta(seconds=172800))
        registration, created = Registration.objects.get_or_create(user_id=user.id)

        # If this is a new registration make sure we at least save the email/username.
        if created:
            logger.debug("User created with ID: {}".format(user.id))
            registration.email = user.username
        else:
            logger.debug("User already existed with ID: {}".format(user.id))

        registration.email_confirmed = True
        registration.save()

        # Save the state of the task
        state.update({
            'state': 'success',
            'message': 'Your email has been confirmed!',
        })

        # Set a message.
        messages.success(request, state['message'], extra_tags='success', fail_silently=True)

    except SignatureExpired as e:
        logger.exception(str(e))
        state.update({
            'state': 'failed',
            'message': 'This email confirmation code has expired, please try again.',
        })

        # Set a message.
        messages.error(request, state['message'], extra_tags='danger', fail_silently=True)

    except Exception as e:
        logger.exception(str(e))
        state.update({
            'state': 'failed',
            'message': 'This email confirmation code is invalid, please try again.',
        })

        # Set a message.
        messages.error(request, state['message'], extra_tags='danger', fail_silently=True)

    # Check for success URL.
    if success_url:
        logger.debug("Success URL: {}".format(success_url))

        # Build the URL.
        url = furl.furl(success_url)

        # Add the state.
        url.args.update(state)

        # Continue on to the next page, if passed. Otherwise render a default page.
        return redirect(url.url)

    else:
        logger.debug("No success URL")

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
        logger.debug("Getting user Profile")

        requested_user = self.request.query_params.get('email', None)
        project = self.request.query_params.get('project', None)
        requesting_user = self.request.user

        # When requesting a specific user or list of users
        if requested_user is not None:

            # If you're trying to someone else's profile, check for permissions
            if requesting_user != requested_user:
                logger.debug("Requested other users profile")

                view_others_permission = sciauthz_services.check_view_profile_permission(self.request.auth, project, requested_user)

                if view_others_permission:
                    logger.debug("Has permission, granting view")
                    return Registration.objects.filter(user__email__iexact=requested_user)
                else:
                    logger.debug("Does not have permission, returning 403")
                    return HttpResponseForbidden()
            else:
                logger.debug("Returning requestor's profile")
                return Registration.objects.filter(user=requesting_user)

        else:
            logger.debug("Returning requestor's profile")
            return Registration.objects.filter(user=requesting_user)

    @list_route(methods=['post'])
    def send_confirmation_email(self, request):
        logger.debug("Send confirmation email")
        user = request.user

        # Build the URL.
        confirm_url = furl.furl(settings.CONFIRM_EMAIL_URL)

        try:
            # Store the data to be passed for verification.
            email_confirm_dict = {}

            # Build the email verification code and b64 encode it.
            signer = TimestampSigner(salt=settings.EMAIL_CONFIRM_SALT)
            signed_value = signer.sign(user.email)
            signed_value = signed_value.split(":")[1] + "." + signed_value.split(":")[2]

            email_confirm_dict['email_confirm_value'] = signed_value

            # Check for a success url and b64 encode it.
            success_url = request.data.get('success_url')
            if success_url:
                logger.debug('Sending email confirmation with success URL: {}'.format(success_url))
                email_confirm_dict['success_url'] = success_url

            # Deserialize and encode the JSON string
            email_confirm_json = json.dumps(email_confirm_dict)
            logger.debug('Sending email confirmation JSON: {}'.format(email_confirm_json))
            email_confirm_parameter = base64.urlsafe_b64encode(bytes(email_confirm_json, 'utf-8')).decode('utf-8')

            # Add the parameters.
            confirm_url.query.params.set('email_confirm_value', email_confirm_parameter)

        except Exception as e:
            logger.exception(e)
            return HttpResponse(status=500)

        logger.debug('Sending email confirmation URL: {}'.format(confirm_url.url))

        # Check for a project id.
        project_id = request.data.get('project', None)
        logger.debug("Email confirmation for project: %s" % project_id)
        if project_id is not None:

            try:
                # Query authz for the project details.
                response = sciauthz_services.get_sciauthz_project(project_id)
                project = response.json()

                # Get the project title and other info
                project_title = project.get('title', 'Harvard Medical School Department of Biomedical Informatics')
                project_icon_url = project.get(project.get('icon_url', 'https://portal.dbmi.hms.harvard.edu/static/hms_dbmi_logo.png'))

                # Add the title and description to the context.
                context = {
                    "confirm_url": confirm_url.url,
                    "user_email": user.email,
                    'project': project_id,
                    'project_title': project_title,
                    'project_description': project.get('description', None),
                    'project_icon_url': project_icon_url
                }

                sent = email_send("{} - E-Mail Verification".format(project_title), user.email,
                           message="verification",
                           extra=context)

            except (requests.ConnectionError, ValueError) as e:
                logger.exception(e)
                logger.debug('Sending email confirmation with default HMS branding')

                # This is a default email verification context with HMS branding
                context = {
                    "confirm_url": confirm_url.url,
                    "user_email": user.email,
                    'project_title': 'Harvard Medical School Department of Biomedical Informatics',
                    'project_icon_url': 'https://portal.dbmi.hms.harvard.edu/static/hms_dbmi_logo.png'
                }

                sent = email_send("Harvard Medical School - E-Mail Verification", user.email,
                           message="verification",
                           extra=context)

        else:
            logger.error("No project ID passed")

            # TODO: Eliminate below, only using PPM branding until SciAuthZ is setup
            sent = email_send("People-Powered Medicine - E-Mail Verification", user.email,
                       message="verify",
                       extra={"confirm_url": confirm_url.url, "user_email": user.email})
            # TODO: Eliminate the above

        # Check the result
        logger.debug('Sending email confirmation was sent: {}'.format(sent))
        if sent:
            return HttpResponse("SENT")
        else:
            return HttpResponse(status=500)

    @list_route(methods=['post'])
    def get_countries(self, request):
        logger.debug("Get distinct countries for list of people")

        project = request.data.get('project', None)
        user = self.request.user

        if project is None:
            logger.error("Project parameter was not supplied.")
            return Response("ERROR: Project parameter was not supplied.", status=status.HTTP_400_BAD_REQUEST)

        jwt_headers = {"Authorization": "JWT " + self.request.auth.decode('utf-8'), 'Content-Type': 'application/json'}
        manage_permission = sciauthz_services.user_has_manage_permission(jwt_headers, project)

        # Only project managers should be allowed to make this call
        if not manage_permission:
            error_message = "User is not authorized to make a get_countries call."
            logger.error(error_message)
            return Response("ERROR: " + error_message, status=status.HTTP_403_FORBIDDEN)

        # Emails should be provided in a comma delimited list
        emails = request.data.get('emails', '').split(',')

        # Build a query that will allow us to match on a list of emails while ignoring casing
        query = reduce(or_, (Q(user__email__iexact=x) for x in emails))
        registrations = Registration.objects.filter(query)

        # Get the distinct countries and the count of each as "n"
        countries = registrations.values("country").annotate(n=Count("country"))

        return Response(data=list(countries), status=status.HTTP_200_OK)


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (AllowAny,)

    def perform_create(self, serializer):

        jwt_string = self.request.POST['JWT']

        try:
            # TODO this method should probably be replaced with the latest py-auth0-jwt authentication methods or maybe this is unnecessary?
            payload = jwt.decode(jwt_string, base64.b64decode(settings.AUTH0_SECRET, '-_'), algorithms=['HS256'], audience=settings.AUTH0_CLIENT_ID)
            logger.debug("User verified JWT successfully")
        except jwt.InvalidTokenError:
            logger.error("User's JWT failed verification")

        if User.objects.filter(email=payload['email']).exists():
            logger.debug("User found, returning")
            return User.objects.filter(email=payload['email'])
        else:
            logger.debug("User not found, creating")
            user = User(username=payload['email'], email=payload['email'])
            user.set_unusable_password()
            user.save()
            return user


def email_send(subject, recipient, message, extra=None):
    """
    Send an e-mail to a list of participants with the given subject and message.
    Extra is dictionary of variables to be swapped into the template.
    """

    logger.debug('Email backend: {}'.format(settings.EMAIL_BACKEND))
    logger.debug('Email SSL: {}'.format(settings.EMAIL_USE_SSL))

    msg_html = render_to_string('email/%s.html' % message, extra)
    msg_plain = render_to_string('email/%s.txt' % message, extra)

    logger.info("About to send email to %s" % recipient)

    try:
        msg = EmailMultiAlternatives(subject, msg_plain, settings.DEFAULT_FROM_EMAIL, [recipient])
        msg.attach_alternative(msg_html, "text/html")
        msg.send()
        logger.info("Email sent successfully")
        return True

    except gaierror as e:
        logger.error("Could not send mail: {}".format(e))
    except Exception as e:
        logger.error("Could not send mail: {}".format(e))
        print(sys.exc_info()[0])

    return False
