from django.conf.urls import url, include
from django.contrib import admin
from django.views.defaults import page_not_found
from pyauth0jwt.auth0authenticate import jwt_login
from registration.views import RegistrationViewSet, UserViewSet

from rest_framework import routers
router = routers.DefaultRouter()
router.register(r'register', RegistrationViewSet)
router.register(r'users', UserViewSet)

urlpatterns = [
    url(r'^admin/login/', page_not_found, {'exception': Exception('Admin form login disabled.')}),
    url(r'^admin/', admin.site.urls),
    url(r'^registration/', include('registration.urls')),
    url(r'^login/$', jwt_login),
    url(r'^api/', include(router.urls)),
    url(r'^', include("registration.urls")),
]
