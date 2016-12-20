from django.conf.urls import url
from .views import register, profile, access

urlpatterns = (
    url(r'^register/$', register),
    url(r'^profile/$', profile),
    url(r'^access/$', access),
    url(r'^$', profile),
)
