from django.urls import re_path, include

from . import views

auth_patterns = [
    re_path(r"^authorize/$", views.AuthorizationView.as_view(), name="authorize"),
    re_path(r"^token/$", views.TokenView.as_view(), name="token"),
    re_path(r"^validate/$", views.AccessTokenValidator.as_view(), name="validate"),
    re_path(r"^get-token/$", views.get_access_token, name="get-access-token"),
]

urlpatterns = auth_patterns
