import json
import logging
import urllib.parse

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, JsonResponse
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
            status = error_response["error"].status_code
            return self.render_to_response(error_response, status=status)

    def redirect(self, redirect_to, application):
        if application is None:
            allowed_schemes = auth_settings.ALLOWED_REDIRECT_URI_SCHEMES
        else:
            allowed_schemes = application.get_allowed_schemes()
        return OAuth2ResponseRedirect(redirect_to, allowed_schemes)


class AuthorizationView(BaseAuthView, FormView):

    def get_initial(self):
        scopes = self.data.get('scope', self.data.get('scopes', []))
        initial_data = {
            "redirect_uri": self.data.get('redirect_uri', None),
            "scope": " ".join(scopes),
            "client_id": self.data.get("client_id", None),
            "state": self.data.get("state", None),
            "response_type": self.data.get("response_type", None),
            "code_challenge": self.data.get("code_challenge", None),
            "code_challenge_method": self.data.get("code_challenge_method", None)
        }
        return initial_data

    def form_valid(self, form):
        client_id = form.cleaned_data.get('client_id', None)
        application = get_application_model().objects.get(client_id=client_id)
        credentials = {
            "client_id": form.cleaned_data.get('client_id'),
            "redirect_uri": form.cleaned_data.get('redirect_uri'),
            "response_type": form.cleaned_data.get('response_type', None),
            "state": form.cleaned_data.get('state', None)
        }
        if form.cleaned_data.get('code_challenge', False):
            credentials['code_challenge'] = form.cleaned_data.get('code_challenge')
        if form.cleaned_data.get('code_challenge_method', False):
            credentials['code_challenge_method'] = form.cleaned_data.get('code_challenge_method')

        scopes = form.cleaned_data.get('scope')
        allow = form.cleaned_data.get('allow')

        try:
            uri, headers, body, status = self.create_authorization_response(
                request=self.request, scopes=scopes, credentials=credentials, allow=allow
            )
        except OAuthToolError as err:
            return self.error_response(err, application)

        self.success_url = uri
        return self.redirect(self.success_url, application)

    def get(self, request, *args, **kwargs):
        """
        Uses Authorization Code Grant Flow.

        Validate the authorization grant request.
        Only accepts response_type `code`.
        After successful validation, send authorization code as response.
        If failure, send error message.
        :param request: current django.HttpRequest object
        """
        try:
            scopes, credentials = self.validate_authorization_request(request)
        except OAuthToolError as err:
            return self.error_response(err, application=None)

        all_scopes = get_scopes_backend().get_all_scopes()
        kwargs["scopes_descriptions"] = [all_scopes[scope] for scope in scopes]
        kwargs["scopes"] = scopes

        # at this point we know an Application instance with such client_id exists in the database

        # TODO: Cache this!
        application = get_application_model().objects.get(client_id=credentials["client_id"])

        kwargs["application"] = application
        kwargs["client_id"] = credentials["client_id"]
        kwargs["redirect_uri"] = credentials["redirect_uri"]
        kwargs["response_type"] = credentials["response_type"]
        kwargs["state"] = credentials["state"]
        if "code_challenge" in credentials:
            kwargs["code_challenge"] = credentials["code_challenge"]
        if "code_challenge_method" in credentials:
            kwargs["code_challenge_method"] = credentials["code_challenge_method"]
        if "nonce" in credentials:
            kwargs["nonce"] = credentials["nonce"]
        if "claims" in credentials:
            kwargs["claims"] = json.dumps(credentials["claims"])

        self.oauth2_data = kwargs
        # following two loc are here only because of https://code.djangoproject.com/ticket/17795
        form = self.get_form(self.get_form_class())
        kwargs["form"] = form

        # Check to see if the user has already granted access and return
        # a successful response depending on "approval_prompt" url parameter
        require_approval = request.GET.get("approval_prompt", auth_settings.REQUEST_APPROVAL_PROMPT)

        try:
            # If skip_authorization field is True, skip the authorization screen even
            # if this is the first use of the application and there was no previous authorization.
            # This is useful for in-house applications-> assume an in-house applications
            # are already approved.
            if application.skip_authorization:
                uri, headers, body, status = self.create_authorization_response(
                    request=self.request, scopes=" ".join(scopes), credentials=credentials, allow=True
                )
                return self.redirect(uri, application)

            elif require_approval == "auto":
                tokens = (
                    get_access_token_model().objects.filter(
                        user=request.user, application=kwargs["application"], expires__gt=timezone.now()
                    ).all()
                )

                # check past authorizations regarded the same scopes as the current one
                for token in tokens:
                    if token.allow_scopes(scopes):
                        uri, headers, body, status = self.create_authorization_response(
                            request=self.request,
                            scopes=" ".join(scopes),
                            credentials=credentials,
                            allow=True,
                        )
                        return self.redirect(uri, application, token)

        except OAuthToolError as error:
            return self.error_response(error, application)

        return self.render_to_response(self.get_context_data(**kwargs))

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
