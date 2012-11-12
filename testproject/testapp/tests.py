import json

from django.test import TestCase
import django.test.client
from django.core.urlresolvers import reverse
from django.contrib.auth.models import User
from django.contrib.sites.models import Site

import oauthlib.oauth1.rfc5849

from restless_oauth.models import *


class OAuthTestClient(django.test.client.Client):

    def __init__(self, *args, **kwargs):
        super(OAuthTestClient, self).__init__(*args, **kwargs)
        self.client_key = None
        self.client_secret = None
        self.access_token = None
        self.access_secret = None
        self.oauth_verifier = None
        self.oauth_uri = None
        self.oauth_client = None

    def _init_oauth_client(self):
        if self.client_key:
            self.oauth_client = oauthlib.oauth1.rfc5849.Client(self.client_key,
                client_secret=self.client_secret,
                resource_owner_key=self.access_token,
                resource_owner_secret=self.access_secret,
                verifier=self.oauth_verifier)
        else:
            self.oauth_client = None

    def set_uri(self, uri):
        self.oauth_uri = unicode(uri)

    def set_client_key(self, client_key, client_secret=None):
        self.client_key = unicode(client_key)
        self.client_secret = unicode(client_secret)
        self._init_oauth_client()

    def set_access_token(self, access_token, access_secret=None):
        self.access_token = unicode(access_token)
        self.access_secret = unicode(access_secret)
        self._init_oauth_client()

    def set_verifier(self, verifier):
        self.oauth_verifier = verifier
        self._init_oauth_client()

    @staticmethod
    def process(response):
        try:
            response.json = json.loads(response.content)
        except Exception:
            response.json = None
        finally:
            return response

    def inject_oauth_headers(self, headers, method):
        if self.oauth_client and self.oauth_uri:
            uri, oauth_headers, body = self.oauth_client.sign(self.oauth_uri,
                http_method=unicode(method))
            headers = dict(headers)
            for k, v in oauth_headers.items():
                headers['HTTP_' + k.upper()] = v
        return headers

    def get(self, url_name, data={}, follow=False, extra={}, *args, **kwargs):
        return self.process(
            super(OAuthTestClient, self).get(
                reverse(url_name, args=args, kwargs=kwargs),
                data=data,
                follow=follow,
                **self.inject_oauth_headers(extra, 'GET')))

    def post(self, url_name, data={}, follow=False, extra={}, *args, **kwargs):
        return self.process(
            super(OAuthTestClient, self).post(
                reverse(url_name, args=args, kwargs=kwargs),
                data=data,
                follow=follow,
                **self.inject_oauth_headers(extra, 'POST')))

    def put(self, url_name, data={}, follow=False, extra={}, *args, **kwargs):
        return self.process(
            super(OAuthTestClient, self).put(
                reverse(url_name, args=args, kwargs=kwargs),
                data=data, follow=follow,
                **self.inject_oauth_headers(extra, 'PUT')))

    def delete(self, url_name, data={}, follow=False, extra={}, *args,
        **kwargs):

        return self.process(
            super(OAuthTestClient, self).delete(
                reverse(url_name, args=args, kwargs=kwargs),
                content_type=content_type, data=data, follow=follow,
                **self.inject_oauth_headers(extra, 'DELETE')))


class OAuthViewTest(TestCase):

    def clean(self):
        User.objects.all().delete()
        OAuthClient.objects.all().delete()
        OAuthRequestToken.objects.all().delete()
        OAuthAccessToken.objects.all().delete()
        OAuthVerifier.objects.all().delete()
        OAuthNonce.objects.all().delete()

    def setUp(self):
        self.clean()

        s = Site.objects.get(id=1)
        s.domain = 'localhost'
        s.save()
        Site.objects.clear_cache()

        self.client_key = u'CLIENTKEYCLIENTKEYCLIENTKEY'
        self.client_secret = u'CLIENTSECRETCLIENTSECRET'
        self.user_key = u'USERKEYUSERKEYUSERKEY'
        self.user_secret = u'USERSECRETUSERSECRET'

        self.user = User.objects.create_user(username='foo', password='bar')
        self.client = OAuthClient.objects.create(key=self.client_key,
            secret=self.client_secret)

        self.testclient = OAuthTestClient()

    def tearDown(self):
        self.clean()

    def test_returns_bad_req_if_no_oauth_signature(self):
        tc = OAuthTestClient()

        r = tc.post('oauth_get_request_token')
        self.assertEqual(r.status_code, 400)

    def test_returns_bad_req_if_invalid_client_key(self):
        tc = OAuthTestClient()
        tc.set_client_key('foo', 'bar')
        tc.set_uri('http://localhost/oauth/request_token')

        r = tc.post('oauth_get_request_token')
        self.assertEqual(r.status_code, 400)
        self.assertTrue('client key' in r.json.get('error', ''))

    def test_returns_bad_req_if_nonexistent_client(self):
        tc = OAuthTestClient()
        tc.set_client_key(u'CLIENTKEYDOESNTEXIST',
            u'CLIENTSECRETDOESNTEXIST')
        tc.set_uri('http://localhost/oauth/request_token')

        r = tc.post('oauth_get_request_token')
        self.assertEqual(r.status_code, 400)
        self.assertTrue('client key' in r.json.get('error', ''))

    def test_returns_unauthorized_on_uri_mismatch(self):
        tc = OAuthTestClient()
        tc.set_client_key(self.client_key, self.client_secret)
        tc.set_uri('http://localhost/incorrect/uri')

        r = tc.post('oauth_get_request_token')
        self.assertEqual(r.status_code, 401)

    def test_get_request_token_succeeds(self):
        tc = OAuthTestClient()
        tc.set_client_key(self.client_key, self.client_secret)
        tc.set_uri('http://localhost/oauth/request_token')

        r = tc.post('oauth_get_request_token')
        self.assertEqual(r.status_code, 200)

        self.assertTrue(OAuthRequestToken.objects.filter(
            token=r.json['oauth_token'],
            secret=r.json['oauth_token_secret']).exists())

    def test_returns_unauthorized_if_request_replay_attempted(self):
        tc = OAuthTestClient()
        tc.set_client_key(self.client_key, self.client_secret)
        tc.set_uri('https://localhost/oauth/request_token')

        r = tc.post('oauth_get_request_token')
        self.assertEqual(r.status_code, 200)

        tc2 = OAuthTestClient()
        r2 = tc2.post('oauth_get_request_token',
            extra={'Authorization': r.request['Authorization']})
        self.assertEqual(r2.status_code, 401)

    def test_get_access_token_succeeds(self):
        request_token = OAuthRequestToken.generate(self.client)
        verifier = OAuthVerifier.generate(self.user, request_token)

        tc = OAuthTestClient()
        tc.set_client_key(self.client_key, self.client_secret)
        tc.set_access_token(request_token.token, request_token.secret)
        tc.set_verifier(verifier.verifier)
        tc.set_uri('http://localhost/oauth/access_token')

        r = tc.post('oauth_get_access_token')
        self.assertEqual(r.status_code, 200)

        self.assertTrue(OAuthAccessToken.objects.filter(
            token=r.json['oauth_token'],
            secret=r.json['oauth_token_secret']).exists())

    def test_get_access_token_returns_bad_req_on_invalid_verifier(self):
        request_token = OAuthRequestToken.generate(self.client)

        tc = OAuthTestClient()
        tc.set_client_key(self.client_key, self.client_secret)
        tc.set_access_token(request_token.token, request_token.secret)
        tc.set_verifier(u'INVALIDVERIFIERKEY')
        tc.set_uri('http://localhost/oauth/access_token')

        r = tc.post('oauth_get_access_token')
        self.assertEqual(r.status_code, 400)
        self.assertTrue('verifier' in r.json.get('error', ''))

    def test_get_access_token_returns_bad_req_on_invalid_request_token(self):
        request_token = OAuthRequestToken.generate(self.client)
        verifier = OAuthVerifier.generate(self.user, request_token)

        tc = OAuthTestClient()
        tc.set_client_key(self.client_key, self.client_secret)
        tc.set_access_token(u'INVALIDREQUESTTOKEN', u'INVALIDREQUESTSECRET')
        tc.set_verifier(verifier.verifier)
        tc.set_uri('http://localhost/oauth/access_token')

        r = tc.post('oauth_get_access_token')
        self.assertEqual(r.status_code, 400)
        self.assertTrue('resource owner key' in r.json.get('error', ''))

    def test_access_protected_resource_fails_without_oauth(self):
        tc = OAuthTestClient()
        tc.set_uri('http://localhost/secret/')

        r = tc.get('protected_endpoint')
        self.assertEqual(r.status_code, 403)

    def test_access_protected_resource_succeeds_with_oauth(self):
        token = OAuthAccessToken.generate(self.user, self.client)

        tc = OAuthTestClient()
        tc.set_client_key(self.client_key, self.client_secret)
        tc.set_access_token(token.token, token.secret)
        tc.set_uri('https://localhost/secret/')

        r = tc.get('protected_endpoint')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json['success'])
