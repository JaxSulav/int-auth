import json
import re
import requests

from urllib.parse import urlparse

from django.contrib.auth import get_user_model, authenticate, login
from django.http import JsonResponse, HttpResponseForbidden
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, status

from .models import PERMISSION_MAPPING, ViewGroupPermission
from .utils import get_user_permissions, map_view_name
from .serializers import UserCreationSerializer
from main.settings import AUTHORIZATION_URL, TOKEN_URL, BASE_URL
from main.utils import encodb64
from provider.models import get_application_model
from provider.views.mixins import OAuthMixin, ProtectedResourceMixin
from users.utils import cache_user_permissions
from utils.response_utils import body_response, error_response, success_response

Application = get_application_model()
User = get_user_model()
AUTHORIZATION_URL = BASE_URL + AUTHORIZATION_URL
TOKEN_URL = BASE_URL + TOKEN_URL


@csrf_exempt
def user_login(request):
    """
    Log in the user.
    If user is authenticated, start the OAuth Authorization Grant flow.
    First obtain the authorization code from authorization endpoint of provider,
    The client_id, client_secret and authorization_code("obtained as access token from response") is passed to
    token endpoint of provider.
    The token endpoint provides the required access_token, refresh_token, expire_time if the request made is valid.
    :param request: a django.HttpRequest object
    """
    if request.method == "POST":
        request_body = json.loads(request.body)
        username = request_body.get('username')
        password = request_body.get('password')
        user = authenticate(username=username, password=password)
        if user:
            if user.is_active:
                login(request, user)
                application = Application.objects.last()
                client_id = application.client_id
                response_type = "code"
                payload = {'client_id': client_id, 'response_type': response_type, 'user_id': user.id}
                code_response = requests.get(AUTHORIZATION_URL, params=payload)
                if code_response.status_code == 200:
                    response_json = json.loads(code_response.content)
                    client_id = response_json['client_id']
                    client_secret = response_json['client_secret']
                    code = response_json['access_token']
                    grant_type = "authorization_code"
                    encoded_key = encodb64(client_id, client_secret).decode('utf-8')

                    # we need to pass the client id and secret in an encoded format
                    headers = {
                        'Authorization': 'Basic {}'.format(encoded_key),
                        'Content-Type': 'x-www-form-urlencoded'
                    }
                    body = {
                        'code': code,
                        'grant_type': grant_type
                    }
                    token_response = requests.post(TOKEN_URL, json=body, headers=headers)
                    if token_response.status_code == 200:
                        token_content = json.loads(token_response.content)
                        token_content['user_id'] = user.id
                        token = token_content.get("access_token", "")
                        if token:
                            cache_user_permissions(token, user)
                        return body_response(token_content, resp_status=status.HTTP_200_OK)
                    else:
                        return error_response(error='Cannot obtain token.', resp_status=token_response.status_code)
                else:
                    return error_response(error='Cannot obtain token.', resp_status=code_response.status_code)
            else:
                return error_response(error='User not active.')
        else:
            return error_response(error='User credentials incorrect.')
    else:
        return error_response(error='Method not allowed.', resp_status=status.HTTP_405_METHOD_NOT_ALLOWED)


class UserRegistration(ProtectedResourceMixin, viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserCreationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = User()
            user.username = serializer.validated_data.get("username")
            user.email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")
            if not self._password_criteria(password):
                return error_response(field='password', error='Password did not meet criteria.')
            user.set_password(password)
            user.save()
            response_body = {
                "message": "User successfully created.",
                "user_id": user.id
            }
            return body_response(response_body, resp_status=status.HTTP_201_CREATED)
        else:
            return error_response(error=serializer.errors)

    def _password_criteria(self, password):
        pattern = r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
        match = re.match(pattern, password)
        if match:
            return True
        return False


class ValidateViewPermission(ProtectedResourceMixin, OAuthMixin, View):
    """
    View to validate if the user can perform the operation on the requested view or not.
    """

    def _extract_params(self, url):
        """
        Extract parameters from the Django request object.
        return application_url,
        """
        params = urlparse(url)
        return params.scheme + "://" + params.netloc, params.path

    def _get_user_groups(self, user):
        groups = user.groups.all()
        return groups

    def get(self, request, *args, **kwargs):
        user = self.request.user
        if user.is_superuser:
            return JsonResponse({
                'msg': 'You can perform the operation'
            }, status=200)
        groups = self._get_user_groups(user)
        application_url, view_path = self._extract_params(request.POST.get('url'))
        operation = 'read'
        try:
            application = Application.objects.get(application_uri=application_url)
        except Application.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': 'This service is not registered in authentication server.'
            }, status=400)
        permission_code = PERMISSION_MAPPING.get(operation, 0)
        view_name = map_view_name(view_path, application.id)
        if ViewGroupPermission.objects.filter(
            group__in=groups,
            view_name=view_name,
            application=application,
            permission__gte=permission_code
        ).exists():
            return JsonResponse({
                'success': True,
                'msg': 'User is permitted to perform this action'
            }, status=200)
        else:
            return JsonResponse({
                'success': False,
                'error': 'not_permitted',
                'error_description': 'User is not permitted to perform this action'
            })

    def post(self, request, *args, **kwargs):
        user = self.request.user
        if user.is_superuser:
            return JsonResponse({
                'success': True,
                'msg': 'User is permitted to perform this action'
            }, status=200)
        groups = self._get_user_groups(user)
        application_url, view_path = self._extract_params(request.POST.get('url'))
        operation = 'write'
        try:
            application = Application.objects.get(application_uri=application_url)
        except Application.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': 'This service is not registered in authentication server.'
            }, status=400)
        permission_code = PERMISSION_MAPPING.get(operation, 2)
        view_name = map_view_name(view_path, application.id)
        if ViewGroupPermission.objects.filter(
            group__in=groups,
            view_name=view_name,
            application=application,
            permission__gte=permission_code
        ).exists():
            return JsonResponse({
                'success': True,
                'msg': 'User is permitted to perform this action'
            }, status=200)
        else:
            return JsonResponse({
                'success': False,
                'error': 'not_permitted',
                'error_description': 'User is not permitted to perform this action'
            })

    def put(self, request, *args, **kwargs):
        user = self.request.user
        if user.is_superuser:
            return JsonResponse({
                'success': True,
                'msg': 'User is permitted to perform this action'
            }, status=200)
        groups = self._get_user_groups(user)
        application_url, view_path = self._extract_params(request.POST.get('url'))
        operation = 'update'
        try:
            application = Application.objects.get(application_uri=application_url)
        except Application.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': 'This service is not registered in authentication server.'
            }, status=400)
        permission_code = PERMISSION_MAPPING.get(operation, 4)
        view_name = map_view_name(view_path, application.id)
        if ViewGroupPermission.objects.filter(
                group__in=groups,
                view_name=view_name,
                application=application,
                permission__gte=permission_code
        ).exists():
            return JsonResponse({
                'success': True,
                'msg': 'User is permitted to perform this action'
            }, status=200)
        else:
            return JsonResponse({
                'success': False,
                'error': 'not_permitted',
                'error_description': 'User is not permitted to perform this action'
            })

    def patch(self, request, *args, **kwargs):
        user = self.request.user
        if user.is_superuser:
            return JsonResponse({
                'success': True,
                'msg': 'User is permitted to perform this action'
            }, status=200)
        groups = self._get_user_groups(user)
        application_url, view_path = self._extract_params(request.POST.get('url'))
        operation = 'update'
        try:
            application = Application.objects.get(application_uri=application_url)
        except Application.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': 'This service is not registered in authentication server.'
            }, status=400)
        permission_code = PERMISSION_MAPPING.get(operation, 4)
        view_name = map_view_name(view_path, application.id)
        if ViewGroupPermission.objects.filter(
                group__in=groups,
                view_name=view_name,
                application=application,
                permission__gte=permission_code
        ).exists():
            return JsonResponse({
                'success': True,
                'msg': 'User is permitted to perform this action'
            }, status=200)
        else:
            return JsonResponse({
                'success': False,
                'error': 'not_permitted',
                'error_description': 'User is not permitted to perform this action'
            })

    def delete(self, request, *args, **kwargs):
        user = self.request.user
        if user.is_superuser:
            return JsonResponse({
                'success': True,
                'msg': 'User is permitted to perform this action'
            }, status=200)
        groups = self._get_user_groups(user)
        application_url, view_path = self._extract_params(request.POST.get('url'))
        operation = 'delete'
        try:
            application = Application.objects.get(application_uri=application_url)
        except Application.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': 'This service is not registered in authentication server.'
            }, status=400)
        view_name = map_view_name(view_path, application.id)
        permission_code = PERMISSION_MAPPING.get(operation, 8)
        if ViewGroupPermission.objects.filter(
                group__in=groups,
                view_name=view_name,
                application=application,
                permission__gte=permission_code
        ).exists():
            return JsonResponse({
                'success': True,
                'msg': 'User is permitted to perform this action'
            }, status=200)
        else:
            return JsonResponse({
                'success': False,
                'error': 'not_permitted',
                'error_description': 'User is not permitted to perform this action'
            })
