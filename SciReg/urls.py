from django.conf.urls import url, include
from django.contrib import admin
from SciReg.auth0authenticate import jwt_login
from registration.views import RegistrationViewSet

from rest_framework import routers
router = routers.DefaultRouter()
router.register(r'register', RegistrationViewSet)

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^registration/', include('registration.urls')),
    url(r'^login/$', jwt_login),
    url(r'^api/', include(router.urls)),
    url(r'^', include("registration.urls")),
]
