from django.urls import re_path

from . import views

auth_patterns = [
    re_path(r"^authorize/$", views.AuthorizationView.as_view(), name="authorize"),
    re_path(r"^token/$", views.TokenView.as_view(), name="token"),
]

urlpatterns = auth_patterns
