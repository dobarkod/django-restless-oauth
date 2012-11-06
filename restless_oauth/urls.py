from django.conf.urls import patterns, url

from .views import *

urlpatterns = patterns('',
    url(r'^request_token$', GetRequestToken.as_view(),
        name='oauth_get_request_token'),
    url(r'^authorize$', Authorize.as_view(),
        name='oauth_authorize'),
    url(r'^access_token$', GetAccessToken.as_view(),
        name='oauth_get_access_token'),
)
