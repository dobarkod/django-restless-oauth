# Create your views here.

from .models import *
from .auth import Server

from restless.views import Endpoint
from restless.http import JSONErrorResponse, Http400

from oauthlib.common import Request as OAuthRequest

from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.sites.models import Site


class Http401(JSONErrorResponse):
    """HTTP 401 Unauthorized (OAuth)"""
    status_code = 401


class OAuthMixin(object):

    @staticmethod
    def _get_http_headers(request):
        def reconstruct(header):
            if header.startswith('HTTP_'):
                header = header[5:]
            header = u'-'.join(h.capitalize() for h in header.split('_'))
            return header

        headers = {}
        for k, v in request.META.items():
            if k.startswith('HTTP_') or k.startswith('CONTENT_'):
                headers[reconstruct(k)] = unicode(v)

        return headers

    @classmethod
    def get_oauth_params(cls, request):
        s = Server()
        r = OAuthRequest(u'?' + unicode(request.META.get('QUERY_STRING', '')),
            http_method=request.method,
            headers=cls._get_http_headers(request),
            body=request.raw_data)
        sigtype, params, oauth_params = s.get_signature_type_and_params(r)
        return dict(oauth_params)

    def verify_oauth_request(self, request, **kwargs):

        def get_absolute_url():
            return u'http%s://%s%s' % ('s' if request.is_secure() else '',
                Site.objects.get_current().domain,
                request.get_full_path())

        server = Server()

        authorized = server.verify_request(
            get_absolute_url(),
            body=request.raw_data,
            http_method=unicode(request.method),
            headers=self._get_http_headers(request),
            **kwargs)

        if not authorized:
            raise Server.Unauthorized()

        params = self.get_oauth_params(request)
        OAuthNonce.generate(params['oauth_consumer_key'],
            params['oauth_timestamp'], params['oauth_nonce'])

        return params

    def authorize_get_request_token(self, request):
        return self.verify_oauth_request(request,
            require_resource_owner=False)

    def authorize_get_access_token(self, request, uri=None):
        return self.verify_oauth_request(request,
            require_verifier=True)

    def authorize_resource(self, request, uri=None):
        return self.verify_oauth_request(request,
            require_resource_owner=True)

    def authenticate(self, request):

        try:
            params = self.authorize_resource(request)
        except:
            return

        try:
            t = OAuthAccessToken.objects.get(token=params.get('oauth_token'))
            request.user = t.user
        except OAuthAccessToken.DoesNotExist:
            return


class GetRequestToken(Endpoint, OAuthMixin):

    def post(self, request):
        try:
            params = self.authorize_get_request_token(request)
        except Server.Unauthorized:
            return Http401('Unauthorized')
        except ValueError as e:
            return Http400('Invalid OAuth params: ' + str(e))

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
        try:
            params = self.authorize_get_access_token(request)
        except Server.Unauthorized:
            return Http401('Unauthorized')
        except ValueError as e:
            return Http400('Invalid OAuth params: ' + str(e))

        verifier = OAuthVerifier.objects.get(verifier=params['oauth_verifier'])

        access_token = OAuthAccessToken.generate(verifier.user,
            verifier.client)

        verifier.request_token.delete()
        verifier.delete()

        return {
            'oauth_token': access_token.token,
            'oauth_token_secret': access_token.secret
        }
