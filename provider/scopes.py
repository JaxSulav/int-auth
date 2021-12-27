from main.settings import auth_settings


class BaseScopes:
    def get_all_scopes(self):
        """
        Return dict-like object including all the scopes defined in the system.
        """
        return NotImplementedError("Every sub-class must implement this method")

    def get_default_scopes(self, application=None, request=None, *args, **kwargs):
        """
        Return list of scopes for current application or request
        This MUST be a subset of the scopes returned by `get_available_scopes`.
        """
        return NotImplementedError("Every sub-class must implement this method")

    def get_available_scopes(self, application=None, request=None, *args, **kwargs):
        """
        Return list of scopes for current application or request
        """
        return NotImplementedError("Every sub-class must implement this method")


class SettingsScopes(BaseScopes):
    def get_all_scopes(self):
        return auth_settings.SCOPES

    def get_available_scopes(self, application=None, request=None, *args, **kwargs):
        return auth_settings._SCOPES

    def get_default_scopes(self, application=None, request=None, *args, **kwargs):
        return auth_settings._DEFAULT_SCOPES


def get_scopes_backend():
    scopes_class = auth_settings.SCOPES_BACKEND_CLASS
    return scopes_class()
