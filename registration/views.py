from django.shortcuts import render
from .forms import RegistrationForm, ProfileForm
from registration.models import Registration
from rest_framework import viewsets, permissions, generics
from registration.serializers import RegistrationSerializer
from registration.permissions import IsAssociatedUser
from django.contrib.auth.decorators import login_required


@login_required
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


@login_required
def access(request, template_name='registration/access.html'):
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
