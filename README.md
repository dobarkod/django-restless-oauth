# Django Restless OAuth

[![Build Status](https://secure.travis-ci.org/dobarkod/django-restless-oauth.png)](http://travis-ci.org/dobarkod/django-restless-oauth)

Django Restless OAuth is an add-on for
[Django Restless](http://github.com/dobarkod/django-restless) for creating
OAuth 1 providers. It uses the low level [oauthlib](https://github.com/idan/oauthlib)
library.

Consider it alpha-quality software. *DO NOT* use in production (esp. see the
security issue described below).

## Installation

Install via Github:

        pip install https://github.com/dobarkod/django-restless-oauth/archive/master.zip

## Quickstart

* Make sure you use the Sites framework and that your site URL is correctly set
(needed for OAuth URL verification)
* Make sure you use HTTPS (oauthlib will complain otherwise, and be right about
it)
* Restless OAuth provides resources for 3-legged OAuth authorization in
`django_restless.urls`. In your project's `urls.py` add:

        import restless_oauth.urls

        urlpatterns += ('',
            url(r'^oauth/', include(restless_oauth.urls))
        )

* In views that should use OAuth authorization, use `OAuthMixin`:

        from restless_oauth.views import OAuthMixin

        class ProtectedEndpoint(Endpoint, OAuthMixin):

            @login_required
            def get(self, request):
                return { 'username': request.user.username }

* OAuthMixin will attempt to authenticate the request and assign request.user
as appropriate; you can use DjangoRestless' `login_required` to make sure
it's set

**WARNING**: `/oauth/authorize` (2nd step in 3-legged OAuth authentication
flow) as implemented by `restless_oauth.views.Authorize` will auto-authorize
any request if the user is logged in. *You MUST override this* and ask the
user whether they authorize the app.

## Documentation

There's not much documentation yet, please see the tests for examples.

## License

Copyright (C) 2012. by Senko Rašić and Django Restless OAuth contributors.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
