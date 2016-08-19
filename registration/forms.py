from django import forms


class RegistrationForm(forms.Form):
    email = forms.CharField(label='E-Mail', max_length=100)
    institution = forms.CharField(label='Institution', max_length=100)