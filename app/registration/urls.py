from django.conf.urls import url
from .views import profile, access, email_send, email_confirm


urlpatterns = (
    url(r'^profile/$', profile, name="profile"),
    url(r'^access/$', access, name="access"),
    url(r'^email_confirm/$', email_confirm, name="email_confirm"),
    url(r'^$', profile),
)
