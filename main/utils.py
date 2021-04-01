import base64

from django.contrib.auth.models import Group

from users.models import ViewGroupPermission, PERMISSION_MAPPING
from provider.models import get_application_model

Application = get_application_model()


def encodb64(client_id, client_secret):
    key = client_id + ':' + client_secret
    message_bytes = key.encode("utf-8")
    base64_bytes = base64.b64encode(message_bytes)
    return base64_bytes


def populate_permissions():
    """
    Populate views permission data to group for different services.
    ToDo: Read from a json file that is stored centrally
    """
    # this is a sample for the json file to be stored centrally
    # service_id is the application id that authentication service uses to identify
    # respective service
    permission_json = [
        {
            'service_id': 1,
            'roles': [
                {'group_name': 'Manager', 'view_name': 'Report', 'permission': 'delete'},
                {'group_name': 'Manager', 'view_name': 'Payment', 'permission': 'read'}
            ]
        }
    ]

    for permission in permission_json:
        application_id = permission.get('service_id', None)
        if not application_id:
            continue
        else:
            try:
                application = Application.objects.get(id=application_id)
            except Application.DoesNotExist:
                continue
        batch_size = 100
        batch_no = 1
        for role in permission['roles'][((batch_no - 1) * batch_size): batch_size * batch_no]:
            group_name = role.get('group_name', None)
            if not group_name:
                continue
            else:
                try:
                    group = Group.objects.get(name=group_name)
                except Group.DoesNotExist:
                    continue
            try:
                ViewGroupPermission.objects.get_or_create(
                    application=application,
                    group=group,
                    view_name=role.get('view_name', ''),
                    permission=PERMISSION_MAPPING.get(role.get('permission', None), 0)
                )
            except Exception as e:
                # exception for duplicate entries
                continue
            finally:
                batch_no += 1
