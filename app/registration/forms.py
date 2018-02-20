from django import forms
from registration.models import Registration


ACADEMIC = 'AC'
INDUSTRY = 'IN'
NONE = ''

SOFTWARE = 'SF'
DATA = 'DT'
TECHNICAL_GUIDANCE = 'TG'

AFFILIATION_CHOICES = (
    (ACADEMIC, 'Academic'),
    (INDUSTRY, 'Industry'),
    (NONE, 'None')
)

DBMI_INTERESTS_CHOICES = (
    (SOFTWARE, 'Software'),
    (DATA, 'Data'),
    (TECHNICAL_GUIDANCE, 'Technical Guidance'),
)


class RegistrationForm(forms.Form):
    email = forms.CharField(label='E-Mail', max_length=100)
    affiliation = forms.CharField(label='Affiliation', max_length=100)


class ProfileForm(forms.ModelForm):

    class Meta:
        model = Registration
        fields = ("email", "email_confirmed")

    email = forms.CharField(disabled=True)
    email_confirmed = forms.BooleanField(disabled=True)
