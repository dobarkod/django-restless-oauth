from django.conf.urls import patterns, include, url
import testapp.urls
import restless_oauth.urls

urlpatterns = patterns('',
    url(r'^oauth/', include(restless_oauth.urls)),
    url('', include(testapp.urls)),
)
