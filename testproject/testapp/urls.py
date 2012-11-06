from django.conf.urls import patterns, url

from .views import *


urlpatterns = patterns('',
    url(r'^secret/$', ProtectedEndpoint.as_view(),
        name='protected_endpoint'),
)
