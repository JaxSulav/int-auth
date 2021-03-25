from django.contrib.auth import get_user_model, authenticate, login
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

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
                return JsonResponse({'msg': 'User successfully logged in.'})
            else:
                return JsonResponse({'msg': 'User not active.'})
        else:
            return JsonResponse({'msg': 'User credentials incorrect.'})
