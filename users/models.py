from django.conf import settings
from django.contrib.auth.models import Group
from django.db import models

from main.settings import auth_settings

PERMISSION_MAPPING = {
    'read': 1,
    'write': 2,
    'edit': 4,
    'delete': 8
}


class ViewGroupPermission(models.Model):
    """
    A ViewGroupPermission instance stores permissions given to a group of users for an application
    defined in auth service.

    Fields:
    * group: Relation to Group table.
    * view_name: Name of the view for which permissions are being defined.
    * application: Relation to Application model which identifies the service.
    * permission: An integer field that stores cumulative sum of roles. The lowest role is `read`
                and highest is `delete`.
                A permission of 1 means that the group has `read` permission
                in the view.
                A permission of 2 means that the group has `write` permission
                in the view.
                A permission of 4 means that the group has `edit` permission
                in the view.
                A permission of 8 means that the group has `delete` permission
                in the view.

    Cumulative permission:
        1. A permission of 3 means that the group has `read` and `write` permissions for a view.
        2. A permission of 6 means that the group has `edit` and `write` permissions for a view.
        3. A permission of 15 means that the group has all the permissions for that view.
        and so on...

    Checking permission:
        1. To check if group has `read` role, the permission number should be in [1, 3, 5, 7, 9, 11, 13, 15]
        2. To check if group has `write` role, the permission number should be in [2, 3, 6, 7, 10, 11, 14, 15]
        3. To check if group has `edit` role, the permission number should be in [4, 5, 6, 7, 12, 13, 14, 15]
        4. To check if group has `delete` role, the permission number should be in [8, 9, 10, 11, 12, 13, 14, 15]
    """
    group = models.ForeignKey(Group, related_name="auth_permissions", on_delete=models.CASCADE)
    view_name = models.CharField(max_length=200)
    application = models.ForeignKey(
        auth_settings.APPLICATION_MODEL,
        related_name="auth_permissions",
        on_delete=models.CASCADE,
        help_text="Name of the service registered in auth service"
    )
    permission = models.IntegerField(default=0)

    class Meta:
        db_table = "application_view_group_permission"

    def __str__(self):
        return '{0} - {1} permission'.format(self.group.name, self.view_name)
