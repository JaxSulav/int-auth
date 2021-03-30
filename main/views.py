import json
import re
import requests

from django.contrib.auth import get_user_model, authenticate, login
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.generic import View
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

