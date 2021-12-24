from django.urls import path

from . import views

urlpatterns = [
    path("login", views.user_login, name="login"),
    path("signup", views.UserRegistration.as_view({'get': 'list', 'post': 'create'}), name="register")
]
