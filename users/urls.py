from django.urls import path

from . import views


urlpatterns = [
    path('perm-validate', views.ValidateViewPermission.as_view(), name="validate-view-perm"),
    path('report-list', views.ReportView.as_view(), name="report-list"),
]
