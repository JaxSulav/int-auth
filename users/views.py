from django.http import HttpResponseForbidden, JsonResponse
from django.views.generic import View

from provider.models import get_application_model
from provider.views.mixins import OAuthMixin, ProtectedResourceMixin
from users.models import PERMISSION_MAPPING, ViewGroupPermission

Application = get_application_model()


class ValidateViewPermission(ProtectedResourceMixin, OAuthMixin, View):
    def get(self, request, *args, **kwargs):
        user = self.request.user
        if user.is_superuser:
            return JsonResponse({
                'msg': 'You can perform the operation'
            }, status=200)
        group = user.groups.last()
        view_name = self.request.GET.get('view_name')
        application_id = self.request.GET.get('application_id', None)
        if not application_id:
            return JsonResponse({
                'msg': 'Missing application id'
            }, status=400)
        try:
            application = Application.objects.get(id=application_id)
        except Application.DoesNotExist:
            return JsonResponse({
                'msg': 'Incorrect application id'
            }, status=400)
        method = self.request.method.upper()
        if method == "POST":
            permission_code = "write"
        elif method == "GET":
            permission_code = "read"
        elif method in ["PUT", "PATCH"]:
            permission_code = "update"
        elif method == "DELETE":
            permission_code = "delete"
        else:
            return JsonResponse({
                'msg': 'Method not allowed'
            }, status=405)
        permission_code = PERMISSION_MAPPING.get(permission_code, 0)

        if ViewGroupPermission.objects.filter(
            group=group,
            view_name=view_name,
            application=application,
            permission__gte=permission_code
        ).exists():
            return JsonResponse({
                'msg': 'You can perform the operation'
            }, status=200)
        else:
            return HttpResponseForbidden()
