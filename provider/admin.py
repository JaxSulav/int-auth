from django.contrib import admin

from .models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_refresh_token_model
)


class ApplicationAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "user_id", "client_type", "authorization_grant_type")
    list_filter = ("client_type", "authorization_grant_type", "skip_authorization")


Application = get_application_model()

admin.site.register(Application, ApplicationAdmin)
