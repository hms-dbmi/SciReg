from django.conf.urls import url
from .views import profile, access


urlpatterns = (
    url(r'^profile/$', profile),
    url(r'^access/$', access),
    url(r'^$', profile),
)
