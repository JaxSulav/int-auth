import json
import re
import requests

from urllib.parse import urlparse

from django.contrib.auth import get_user_model, authenticate, login
from django.http import JsonResponse, HttpResponseForbidden
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt

from provider.views.mixins import OAuthMixin, ProtectedResourceMixin
from users.models import PERMISSION_MAPPING, ViewGroupPermission
from users.utils import get_user_permissions, map_view_name

from main.settings import AUTHORIZATION_URL, TOKEN_URL
from main.utils import encodb64
from provider.models import get_application_model
from users.utils import cache_user_permissions

Application = get_application_model()
User = get_user_model()


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
        username = request.POST.get('username')
        password = request.POST.get('password')
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
                        token = token_content.get("access_token", "")
                        if token:
                            cache_user_permissions(token, user)
                        return JsonResponse(token_content, status=200)
                    else:
                        return JsonResponse({'msg': 'Unable to get token'}, status=token_response.status_code)
                else:
                    return JsonResponse({'msg': 'Cannot obtain token.'}, status=code_response.status_code)
            else:
                return JsonResponse({'msg': 'User not active.'}, status=400)
        else:
            return JsonResponse({'msg': 'User credentials incorrect.'}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class UserRegistration(View):
    username = ""
    email = ""
    password1 = ""
    password2 = ""

    def _validate_username(self):
        if User.objects.filter(username=self.username).exists():
            return False, 'User with this username already exists.'
        if self.username == '':
            return False, 'Username should not be empty.'
        return True, ''

    def _validate_email(self):
        if User.objects.filter(email=self.email).exists():
            return False, 'User with this email already exists.'
        if self.email == '':
            return False, 'Email not valid.'
        return True, ''

    def _compare_passwords(self):
        if not self.password1 == self.password2:
            return False
        return True

    def _password_criteria(self):
        pattern = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"
        match = re.match(pattern, self.password1)
        if match:
            return True
        return False

    def _validate_password(self):
        match = self._compare_passwords()
        if not match:
            return False, 'Passwords did not match'
        satisfied = self._password_criteria()
        if not satisfied:
            return False, 'Password did not meet criteria.'
        return True, ''

    def error_response(self, field, error):
        return JsonResponse({field: error}, status=400)

    def post(self, request):
        self.username = request.POST.get('username')
        self.email = request.POST.get('email')
        self.password1 = request.POST.get('password1')
        self.password2 = request.POST.get('password2')
        # and other required fields to register the user

        valid_username, msg = self._validate_username()
        if not valid_username:
            return self.error_response('username', msg)
        valid_email, msg = self._validate_email()
        if not valid_email:
            return self.error_response('email', msg)
        valid_password, msg = self._validate_password()
        if not valid_password:
            return self.error_response('password', msg)

        # if fields are validated
        user = User.objects.create(
            username=self.username,
            email=self.email,
        )
        user.set_password(self.password1)
        user.save()
        return JsonResponse({
            'msg': 'User successfully created.',
            'user_id': user.id
        }, status=200)


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


class ReportView(ProtectedResourceMixin, OAuthMixin, View):
    def get(self, request, *args, **kwargs):
        auth = request.headers.get("AUTHORIZATION", None)
        splitted = auth.split(" ", 1)
        auth_type, auth_string = splitted
        permissions = get_user_permissions(auth_string)
        view_name = "Report"
        # for read
        perm = 1
        if any((item['view_name'] == view_name and item['permission'] >= perm) for item in permissions):
            return JsonResponse({
                'msg': 'Authorization granted'
            }, status=200)
        return JsonResponse({
            'error': 'unauthorized_access',
            'error_description': 'Unauthorized access'
        }, status=403)
