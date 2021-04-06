from urllib.parse import urlparse

from django.http import HttpResponseForbidden, JsonResponse
from django.views.generic import View

from provider.models import get_application_model
from provider.views.mixins import OAuthMixin, ProtectedResourceMixin
from users.models import PERMISSION_MAPPING, ViewGroupPermission
from users.utils import get_user_permissions, map_view_name

Application = get_application_model()


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
