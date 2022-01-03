from django.urls import path

from . import views

urlpatterns = [
    path("login", views.UserLoginView.as_view(), name="login"),
    path("signup", views.UserRegistration.as_view({'get': 'list', 'post': 'create'}), name="register")
]
