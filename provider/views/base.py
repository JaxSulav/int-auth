import json
import logging
import urllib.parse

from django.contrib.auth import get_user_model
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt

from .mixins import OAuthMixin
from main.settings import auth_settings
from provider.exceptions import OAuthToolError
from provider.http import OAuth2ResponseRedirect
from provider.models import get_application_model, get_access_token_model

log = logging.getLogger(__name__)
User = get_user_model()
AccessToken = get_access_token_model()


class BaseAuthView(OAuthMixin, View):
    def dispatch(self, *args, **kwargs):
        self.data = {}
        return super().dispatch(*args, **kwargs)

    def error_response(self, error, application, **kwargs):
        redirect, error_response = super().error_response(error, **kwargs)
        if redirect:
            return self.redirect(error_response["url"], application)
        else:
            return HttpResponseBadRequest(
                "Evil client is unable to send proper request. Error is: {}".format(error_response['error']),
                status=error_response["error"].status_code
            )

    def redirect(self, redirect_to, application):
        if application is None:
            allowed_schemes = auth_settings.ALLOWED_REDIRECT_URI_SCHEMES
        else:
            allowed_schemes = application.get_allowed_schemes()
        return OAuth2ResponseRedirect(redirect_to, allowed_schemes)


class AuthorizationView(BaseAuthView):
    def get(self, request, *args, **kwargs):
        try:
            user = User.objects.get(id=request.GET.get('user_id'))
        except User.DoesNotExist:
            return JsonResponse({'msg': 'User does not exist.'})
        try:
            scopes, credentials = self.validate_authorization_request(request)
        except OAuthToolError as err:
            return self.error_response(err, application=None)
        credentials["user"] = user
        application = get_application_model().objects.get(client_id=credentials["client_id"])

        uri, headers, body, status = self.create_authorization_response(
            request=self.request, scopes=" ".join(scopes), credentials=credentials, allow=True
        )
        return self.redirect(uri, application)

    def redirect(self, redirect_to, application, token=None):
        """
        Redirects to the desired redirect_uri if stated.
        Else returns a JsonResponse including code.
        Currently only return the JsonResponse
        """
        parsed_redirect = urllib.parse.urlparse(redirect_to)
        try:
            error = urllib.parse.parse_qs(parsed_redirect.query)["error"][0]
            response = {
                "error": error
            }
        except KeyError:
            response = {
                "error": 'Cannot generate code'
            }
        try:
            code = urllib.parse.parse_qs(parsed_redirect.query)["code"][0]
            response = {
                "access_token": code,
                "token_uri": redirect_to,
                "client_id": application.client_id,
                "client_secret": application.client_secret,
            }
        except KeyError:
            pass

        return JsonResponse(response)


@method_decorator(csrf_exempt, name="dispatch")
class TokenView(OAuthMixin, View):
    """
    Implements an endpoint to provide access tokens
    The endpoint is used in the following flows:
    * Authorization code
    * Password
    * Client credentials
    """
    def post(self, request, *args, **kwargs):
        url, headers, body, status = self.create_token_response(request)
        response = HttpResponse(content=body, status=status)

        for k, v in headers.items():
            response[k] = v
        return response


@method_decorator(csrf_exempt, name="dispatch")
class AccessTokenValidator(View):
    """
    Implements an endpoint to check whether the given access token is valid
    """
    def post(self, request, *args, **kwargs):
        request_body = json.loads(request.body)
        access_token = request_body.get('access_token')
        user_id = request_body.get('user_id')
        user_access_token = AccessToken.objects.filter(user_id=user_id, invalid=False).last()
        if user_access_token:
            if user_access_token.token == access_token and not user_access_token.is_expired():
                return JsonResponse({
                    'message': 'Validation success.'
                }, status=200)
            else:
                return JsonResponse({
                    'message': "Invalid Token."
                }, status=400)
        else:
            return JsonResponse({
                'message': "Invalid Token."
            }, status=400)
