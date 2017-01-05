from django.contrib import admin
from .models import Registration


class RegistrationAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'first_name', 'last_name')

admin.site.register(Registration, RegistrationAdmin)
