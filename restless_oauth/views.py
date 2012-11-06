# Create your views here.

from .models import *
from .auth import Server

from restless.views import Endpoint
from restless.http import JSONErrorResponse, Http400

from oauthlib.oauth1.rfc5849 import signature

from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.sites.models import Site


class Http401(JSONErrorResponse):
    """HTTP 401 Unauthorized (OAuth)"""
    status_code = 401


class OAuthMixin(object):

    @staticmethod
    def get_absolute_url(uri, https=True):
        return u'http%s://%s%s' % ('s' if https else '',
            Site.objects.get_current().domain, uri)

    @staticmethod
    def get_oauth_params(request):
        return dict(signature.collect_parameters(headers=request.META,
                exclude_oauth_signature=False))

    def authorize_get_request_token(self, request, uri=None):
        server = Server()

        try:
            authorized = server.verify_request(
                self.get_absolute_url(uri or request.get_full_path()),
                body=request.raw_data,
                headers=request.META,
                require_resource_owner=False)
            if not authorized:
                return None, Http401('Unauthorized')
        except ValueError as e:
            return None, Http400('Invalid OAuth params: ' + str(e))

        params = self.get_oauth_params(request)
        OAuthNonce.generate(params['oauth_consumer_key'],
            params['oauth_timestamp'], params['oauth_nonce'])

        return params, None

    def authorize_get_access_token(self, request, uri=None):
        server = Server()

        try:
            authorized = server.verify_request(
                self.get_absolute_url(uri or request.get_full_path()),
                body=request.raw_data,
                headers=request.META,
                require_verifier=True)
            if not authorized:
                return None, Http401('Unauthorized')
        except ValueError as e:
            return None,  Http400('Invalid OAuth params: ' + str(e))

        params = self.get_oauth_params(request)
        OAuthNonce.generate(params['oauth_consumer_key'],
            params['oauth_timestamp'], params['oauth_nonce'])

        return params, None

    def authorize_resource(self, request, uri=None):
        server = Server()

        try:
            authorized = server.verify_request(
                self.get_absolute_url(uri or request.get_full_path()),
                body=request.raw_data,
                headers=request.META,
                require_resource_owner=True)
            if not authorized:
                return None, Http401('Unauthorized')
        except ValueError as e:
            return None, Http400('Invalid OAuth params: ' + str(e))

        params = self.get_oauth_params(request)
        OAuthNonce.generate(params['oauth_consumer_key'],
            params['oauth_timestamp'], params['oauth_nonce'])

        return params, None

    def authenticate(self, request):

        params, error = self.authorize_resource(request)
        if error:
            return

        try:
            t = OAuthAccessToken.objects.get(token=params.get('oauth_token'))
            request.user = t.user
        except OAuthAccessToken.DoesNotExist:
            return


class GetRequestToken(Endpoint, OAuthMixin):

    def post(self, request):
        params, error = self.authorize_get_request_token(request)
        if error:
            return error

        client = OAuthClient.objects.get(key=params.get('oauth_consumer_key'))
        callback = params.get('oauth_callback')

        request_token = OAuthRequestToken.generate(client, callback)
        return {
            'oauth_token': request_token.token,
            'oauth_token_secret': request_token.secret,
        }


class Authorize(Endpoint):

    @method_decorator(login_required)
    def get(self, request):

        try:
            request_token = OAuthRequestToken.objects.get(
                token=request.GET.get('request_token'))
        except OAuthRequestToken.DoesNotExist:
            return Http400('Nonexistent request token')

        verifier = OAuthVerifier.generate(request.user, request_token)

        return {'oauth_verifier': verifier.verifier}


class GetAccessToken(Endpoint, OAuthMixin):

    def post(self, request):
        params, error = self.authorize_get_access_token(request)
        if error:
            return error

        verifier = OAuthVerifier.objects.get(verifier=params['oauth_verifier'])

        access_token = OAuthAccessToken.generate(verifier.user,
            verifier.client)

        verifier.request_token.delete()
        verifier.delete()

        return {
            'oauth_token': access_token.token,
            'oauth_token_secret': access_token.secret
        }
