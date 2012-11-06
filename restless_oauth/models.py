from django.db import models
from django.contrib.auth.models import User

from oauthlib.common import generate_token


class OAuthNonce(models.Model):

    client_key = models.CharField(max_length=255)
    timestamp = models.IntegerField()
    nonce = models.CharField(max_length=255)
    request_token = models.CharField(max_length=255, default='', blank=True)
    access_token = models.CharField(max_length=255, default='', blank=True)

    class Meta:
        unique_together = ('timestamp', 'nonce')

    @staticmethod
    def generate(client_key, timestamp, nonce):
        return OAuthNonce.objects.create(client_key=client_key,
            timestamp=timestamp, nonce=nonce)


class OAuthClient(models.Model):

    key = models.CharField(max_length=255, unique=True)
    secret = models.CharField(max_length=255)
    default_callback = models.URLField(max_length=255, default='',
        blank=True)


class OAuthRequestToken(models.Model):

    client = models.ForeignKey(OAuthClient, related_name='request_tokens')
    token = models.CharField(max_length=255)
    secret = models.CharField(max_length=255)
    callback = models.URLField(max_length=255, default='',
        blank=True)

    class Meta:
        unique_together = ('client', 'token')

    @staticmethod
    def generate(client, callback=None):
        if callback is None:
            callback = client.default_callback

        return OAuthRequestToken.objects.create(
            client=client,
            token=generate_token(),
            secret=generate_token(),
            callback=callback)


class OAuthAccessToken(models.Model):

    client = models.ForeignKey(OAuthClient, related_name='access_tokens')
    user = models.ForeignKey(User, related_name='access_tokens')
    token = models.CharField(max_length=255)
    secret = models.CharField(max_length=255)

    class Meta:
        unique_together = ('client', 'token')

    @staticmethod
    def generate(user, client):
        return OAuthAccessToken.objects.create(
            client=client,
            user=user,
            token=generate_token(),
            secret=generate_token())


class OAuthVerifier(models.Model):

    client = models.ForeignKey(OAuthClient, related_name='verifiers')
    user = models.ForeignKey(User, related_name='verifiers')
    request_token = models.ForeignKey(OAuthRequestToken,
        related_name='verifiers')
    verifier = models.CharField(max_length=255)

    class Meta:
        unique_together = ('client', 'request_token', 'verifier')

    @staticmethod
    def generate(user, request_token):
        return OAuthVerifier.objects.create(
            user=user,
            client=request_token.client,
            request_token=request_token,
            verifier=generate_token())
