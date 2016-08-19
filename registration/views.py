from django.shortcuts import render
from .forms import RegistrationForm
from django.http import HttpResponseRedirect


def register(request, template_name='registration/register.html'):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # process the data in form.cleaned_data as required
            # ...
            # redirect to a new URL:
            return HttpResponseRedirect('/thanks/')
    else:
        form = RegistrationForm()

    return render(request, template_name, {'form': form})




