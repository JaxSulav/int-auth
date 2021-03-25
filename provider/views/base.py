import json
import logging
import urllib.parse

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.generic import FormView, View
from django.views.decorators.csrf import csrf_exempt

from .mixins import OAuthMixin
from main.settings import auth_settings
from provider.exceptions import OAuthToolError
from provider.http import OAuth2ResponseRedirect
from provider.models import get_application_model, get_access_token_model
from provider.scopes import get_scopes_backend

log = logging.getLogger(__name__)


class BaseAuthView(LoginRequiredMixin, OAuthMixin, View):
    def dispatch(self, *args, **kwargs):
        self.data = {}
        return super().dispatch(*args, **kwargs)

    def error_response(self, error, application, **kwargs):
        redirect, error_response = super().error_response(error, **kwargs)
        if redirect:
            return self.redirect(error_response["url"], application)
        else:
            print(error_response["error"])
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
            scopes, credentials = self.validate_authorization_request(request)
        except OAuthToolError as err:
            return self.error_response(err, application=None)

        application = get_application_model().objects.get(client_id=credentials["client_id"])

        uri, headers, body, status = self.create_authorization_response(
            request=self.request, scopes=" ".join(scopes), credentials=credentials, allow=True
        )
        return self.redirect(uri, application)

    def redirect(self, redirect_to, application, token=None):
        if not redirect_to.startswith("urn:ietf:wg:oauth:2.0:oob"):
            return super().redirect(redirect_to, application)

        parsed_redirect = urllib.parse.urlparse(redirect_to)
        code = urllib.parse.parse_qs(parsed_redirect.query)["code"][0]

        if redirect_to.startswith("urn:ietf:wg:oauth:2.0:oob:auto"):
            response = {
                "access_token": code,
                "token_uri": redirect_to,
                "client_id": application.client_id,
                "client_secret": application.client_secret,
                "revoke_uri": reverse("oauth2_provider:revoke-token"),
            }

            return JsonResponse(response)

        else:
            return render(
                request=self.request,
                template_name="oauth2_provider/authorized-oob.html",
                context={
                    "code": code,
                },
            )
