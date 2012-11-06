from restless.views import Endpoint
from restless.auth import login_required
from restless_oauth.views import OAuthMixin

__all__ = ['ProtectedEndpoint']


class ProtectedEndpoint(Endpoint, OAuthMixin):

    @login_required
    def get(self, request):
        return {'success': True}
