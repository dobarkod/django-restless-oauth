import oauthlib.oauth1

from .models import OAuthNonce, OAuthClient, OAuthRequestToken, \
    OAuthAccessToken, OAuthVerifier


class Server(oauthlib.oauth1.Server):

    class Unauthorized(Exception):
        pass

    @property
    def dummy_client_key(self):
        return u'-'

    @property
    def dummy_client(self):
        return None

    @property
    def dummy_resource_owner(self):
        return u'-'

    @property
    def dummy_request_token(self):
        return u'-'

    @property
    def dummy_access_token(self):
        return u'-'

    def get_client_secret(self, client_key):
        try:
            client = OAuthClient.objects.get(key=client_key)
            return client.secret
        except OAuthClient.DoesNotExist:
            raise ValueError('Invalid client key')

    def get_request_token_secret(self, client_key, request_token):
        try:
            rt = OAuthRequestToken.objects.get(client__key=client_key,
                token=request_token)
            return rt.secret
        except OAuthRequestToken.DoesNotExist:
            raise ValueError('Invalid request token')

    def get_access_token_secret(self, client_key, access_token):
        if access_token is None:
            return None

        try:
            at = OAuthAccessToken.objects.get(client__key=client_key,
                token=access_token)
            return at.secret
        except OAuthAccessToken.DoesNotExist:
            raise ValueError('Invalid access token')

    def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
        request_token=None, access_token=None):

        return not OAuthNonce.objects.filter(timestamp=timestamp,
            nonce=nonce).exists()

    def validate_client_key(self, client_key):
        return OAuthClient.objects.filter(key=client_key).exists()

    def validate_request_token(self, client_key, request_token):
        return OAuthRequestToken.objects.filter(client__key=client_key,
            token=request_token).exists()

    def validate_access_token(self, client_key, access_token):
        return OAuthAccessToken.objects.filter(client__key=client_key,
            token=access_token).exists()

    def validate_redirect_uri(self, client_key, redirect_uri):
        # FIXME: we don't whitelist redirect URIs for the moment
        return True

    def validate_requested_realm(self, client_key, realm):
        # FIXME: we don't use realms for the moment
        return True

    def validate_realm(self, client_key, access_token, uri=None,
        required_realm=None):
        # FIXME: we don't use realms for the moment
        return True

    def validate_verifier(self, client_key, request_token, verifier):
        return OAuthVerifier.objects.filter(client__key=client_key,
            request_token__token=request_token, verifier=verifier).exists()
