from django.contrib.auth.mixins import LoginRequiredMixin
from django.forms.models import modelform_factory
from django.shortcuts import render
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

from ..models import get_application_model


class ApplicationOwnerIsUserMixin(LoginRequiredMixin):
    """
    This mixin is used to provide an Application queryset filtered by current request.user.
    """
    fields = "__all__"

    def get_queryset(self):
        return get_application_model().objects.filter(user=self.request.user)


class ApplicationRegistration(LoginRequiredMixin, CreateView):
    """
    View used to register a new Application for the request.user
    """

    def get_form_class(self):
        """
        Returns the form class for the application model
        """
        return modelform_factory(
            get_application_model(),
            fields=(
                "name",
                "client_id",
                "client_secret",
                "client_type",
                "authorization_grant_type",
                "redirect_uris"
            )
        )

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super().form_valid(form)


class ApplicationUpdate(ApplicationOwnerIsUserMixin, UpdateView):
    """
    View used to update an application owned by the request.user
    """
    context_object_name = "application"

    def get_form_class(self):
        """
        Returns the form class for the application model
        """
        return modelform_factory(
            get_application_model(),
            fields=(
                "name",
                "client_id",
                "client_secret",
                "client_type",
                "authorization_grant_type",
                "redirect_uris"
            )
        )
