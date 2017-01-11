from django import forms
from registration.models import Registration


ACADEMIC = 'AC'
INDUSTRY = 'IN'

SOFTWARE = 'SF'
DATA = 'DT'
TECHNICAL_GUIDANCE = 'TG'

AFFILIATION_CHOICES = (
    (ACADEMIC, 'Academic'),
    (INDUSTRY, 'Industry')
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
        fields = ("email", "affiliation", "affiliation_type", "software_interest", "data_interest", "technical_consult_interest")
