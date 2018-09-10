from django.conf.urls import url, include
from django.contrib import admin
from django.views.defaults import page_not_found
from pyauth0jwt.auth0authenticate import jwt_login
from registration.views import RegistrationViewSet

from rest_framework import routers
router = routers.DefaultRouter()
router.register(r'register', RegistrationViewSet)

urlpatterns = [
    url(r'^admin/login/', page_not_found, {'exception': Exception('Admin form login disabled.')}),
    url(r'^admin/', admin.site.urls, name='admin'),
    url(r'^registration/', include('registration.urls', namespace='registration')),
    url(r'^login/$', jwt_login, name='login'),
    url(r'^api/', include(router.urls, namespace='api')),
    url(r'^healthcheck/?', include('health_check.urls')),
    url(r'^', include("registration.urls")),
]
