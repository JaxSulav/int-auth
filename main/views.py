import json
import requests

from django.contrib.auth import get_user_model, authenticate, login
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .settings import AUTHORIZATION_URL, TOKEN_URL
from .utils import encodb64
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
                        return JsonResponse(token_content)
                    else:
                        return JsonResponse({'msg': 'Unable to get token'})
                else:
                    return JsonResponse({'msg': 'Cannot obtain token.'})
            else:
                return JsonResponse({'msg': 'User not active.'})
        else:
            return JsonResponse({'msg': 'User credentials incorrect.'})
