import json
import re
import urllib.parse

from urllib.parse import urlparse

from django.contrib.auth import get_user_model, authenticate, login
from django.http import JsonResponse, HttpResponse
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, status

from .models import PERMISSION_MAPPING, ViewGroupPermission
from .utils import map_view_name
from .serializers import UserCreationSerializer
from main.utils import encodb64
from provider.exceptions import OAuthToolError
from provider.models import get_application_model
from provider.views.mixins import OAuthMixin, ProtectedResourceMixin
from utils.response_utils import body_response, error_response, success_response

Application = get_application_model()
User = get_user_model()


@method_decorator(csrf_exempt, name='dispatch')
class UserLoginView(OAuthMixin, View):

    def delete_params(self, request):
        updated_request = request.GET.copy()

        del updated_request['user_id']
        del updated_request['client_id']
        del updated_request['response_type']

        request.META["QUERY_STRING"] = ""

    def post(self, request, *args, **kwargs):
        request_body = json.loads(request.body)
        username = request_body.get('username')
        password = request_body.get('password')
        if not username or not password:
            return error_response(error="Username or password is missing.")
        user = authenticate(username=username, password=password)
        if user:
            if user.is_active:
                login(request, user)
                application = Application.objects.last()
                client_id = application.client_id
                user_id = user.id
                response_type = "code"

                # add extra data to request.GET
                request.GET = request.GET.copy()
                update_dict = {"client_id": client_id, "user_id": user_id, "response_type": response_type}
                request.GET.update(update_dict)

                request.META["QUERY_STRING"] = f"user_id={user_id}&client_id={client_id}&response_type={response_type}"

                try:
                    scopes, credentials = self.validate_authorization_request(request)
                except OAuthToolError:
                    return error_response(error="Cannot obtain token.")
                credentials["user_id"] = user_id
                application = get_application_model().objects.get(client_id=credentials["client_id"])

                uri, headers, body, status = self.create_authorization_response(
                    request=self.request, scopes=" ".join(scopes), credentials=credentials, allow=True
                )
                response_body = self.redirect(uri, application)
                client_secret = response_body['client_secret']
                code = response_body['access_token']
                grant_type = "authorization_code"
                encoded_key = encodb64(client_id, client_secret).decode('utf-8')
                headers = {
                    'HTTP_AUTHORIZATION': 'Basic {}'.format(encoded_key),
                    'CONTENT_TYPE': 'multipart/formdata'
                }
                body = {
                    'code': code,
                    'grant_type': grant_type
                }

                self.delete_params(request)

                request.POST.update(body)
                request.META.update(headers)

                try:
                    url, headers, body, status = self.create_token_response(request)
                except OAuthToolError:
                    return error_response(error="Cannot obtain access token.")
                response = HttpResponse(content=body, status=status)
                for k, v in headers.items():
                    response[k] = v
                return response
            else:
                return error_response(error="User is not activated.")
        return error_response(error="Invalid user credentials.")

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

        return response


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
