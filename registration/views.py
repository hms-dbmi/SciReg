from django.shortcuts import render
from .forms import RegistrationForm, ProfileForm
from registration.models import Registration
from django.http import HttpResponseRedirect

import logging

# Get an instance of a logger
logger = logging.getLogger(__name__)

def register(request, template_name='registration/register.html'):

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # process the data in form.cleaned_data as required
            # ...
            # redirect to a new URL:
            return HttpResponseRedirect('/registration/profile/')
    else:
        form = RegistrationForm()

    return render(request, template_name, {'form': form})


def profile(request, template_name='registration/profile.html'):
    user = request.user

    if request.method == 'POST':

        form = ProfileForm(request.POST)

        if form.is_valid():
            registration, created = Registration.objects.get_or_create(user_id=user.id)

            registration.email = form.cleaned_data['email']
            registration.affiliation = form.cleaned_data['affiliation']
            registration.affiliation_type = form.cleaned_data['affiliation_type']
            registration.data_interest = form.cleaned_data['data_interest']
            registration.software_interest = form.cleaned_data['software_interest']
            registration.technical_consult_interest = form.cleaned_data['technical_consult_interest']
            registration.save()

            return render(request, template_name, {'form': form})
    else:
        registration, created = Registration.objects.get_or_create(user_id=user.id)

        registration.email = user.username
        form = ProfileForm(instance=registration)

    return render(request, template_name, {'form': form, 'user': user, 'jwt': request.COOKIES.get("DBMI_JWT", None)})


def access(request, template_name='registration/access.html'):
    return render(request, template_name)


