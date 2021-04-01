from django.contrib.auth.models import Group
from django.db import models

from main.settings import auth_settings

PERMISSION_MAPPING = {
    'read': 1,
    'write': 2,
    'update': 4,
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
    * permission: An integer field that stores roles in integer format. The lowest role is `read`
                and highest is `delete`.
                A permission of 1 means that the group has `read` permission
                in the view.
                A permission of 2 means that the group has `write` permission along with lower level permissions
                in the view.
                A permission of 4 means that the group has `update` permission along with lower level permissions
                in the view.
                A permission of 8 means that the group has `delete` permission along with lower level permissions
                in the view.
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
        unique_together = ('group', 'view_name', 'application', 'permission')

    def __str__(self):
        return '{0} - {1} permission'.format(self.group.name, self.view_name)
