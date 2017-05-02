from django.conf.urls import url
from .views import profile, access, email_send, email_confirm


urlpatterns = (
    url(r'^profile/$', profile),
    url(r'^access/$', access),
    url(r'^email_confirm/$', email_confirm),
    url(r'^$', profile),
)
