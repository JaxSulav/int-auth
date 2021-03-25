import json
import requests

from django.contrib.auth import get_user_model, authenticate, login
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .settings import AUTHORIZATION_URL
from provider.models import get_application_model

Application = get_application_model()
User = get_user_model()


@csrf_exempt
def user_login(request):
    """
    Log in the user.
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
                response = requests.get(AUTHORIZATION_URL, params=payload)
                if response.status_code == 200:
                    response_json = json.loads(response.content)
                    return JsonResponse({'msg': 'User successfully logged in.'})
                else:
                    return JsonResponse({'msg': 'Cannot obtain token.'})
            else:
                return JsonResponse({'msg': 'User not active.'})
        else:
            return JsonResponse({'msg': 'User credentials incorrect.'})
