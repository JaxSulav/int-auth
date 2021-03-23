from django.conf import settings
from django.utils.module_loading import import_string

AUTH_PROVIDER = {
    "CLIENT_ID_GENERATOR_CLASS": "provider.generators.ClientIdGenerator",
    "CLIENT_SECRET_GENERATOR_CLASS": "provider.generators.ClientSecretGenerator"
}

USER_SETTINGS = getattr(settings, 'AUTH_PROVIDER', None)

APPLICATION_MODEL = getattr(settings, "PROVIDER_APPLICATION_MODEL", "provider.Application")
ACCESS_TOKEN_MODEL = getattr(settings, "PROVIDER_ACCESS_TOKEN_MODEL", "provider.AccessToken")
ID_TOKEN_MODEL = getattr(settings, "PROVIDER_ID_TOKEN_MODEL", "provider.IDToken")
# GRANT_MODEL = getattr(settings, "PROVIDER_GRANT_MODEL", "provider.Grant")
REFRESH_TOKEN_MODEL = getattr(settings, "PROVIDER_REFRESH_TOKEN_MODEL", "provider.RefreshToken")

DEFAULTS = {
    "CLIENT_ID_GENERATOR_CLASS": "provider.generators.ClientIdGenerator",
    "CLIENT_SECRET_GENERATOR_CLASS": "provider.generators.ClientSecretGenerator",
    "CLIENT_SECRET_GENERATOR_LENGTH": 128,
    "APPLICATION_MODEL": APPLICATION_MODEL,
    "ACCESS_TOKEN_MODEL": ACCESS_TOKEN_MODEL,
    "REFRESH_TOKEN_MODEL": REFRESH_TOKEN_MODEL,
    "ID_TOKEN_MODEL": ID_TOKEN_MODEL,
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": 60,
    "ACCESS_TOKEN_EXPIRE_SECONDS": 3600,
    "ID_TOKEN_EXPIRE_SECONDS": 3600,
    "REFRESH_TOKEN_EXPIRE_SECONDS": None,
    "ALLOWED_REDIRECT_URI_SCHEMES": ["http", "https"],
}

IMPORT_STRINGS = (
    "CLIENT_ID_GENERATOR_CLASS",
    "CLIENT_SECRET_GENERATOR_CLASS",
)

MANDATORY = (
    "CLIENT_ID_GENERATOR_CLASS",
    "CLIENT_SECRET_GENERATOR_CLASS",
)


def perform_import(val, setting_name):
    """
    If the given setting is a string import notation,
    then perform the necessary import or imports.
    """
    if val is None:
        return None
    elif isinstance(val, str):
        return import_from_string(val, setting_name)
    elif isinstance(val, (list, tuple)):
        return [import_from_string(item, setting_name) for item in val]
    return val


def import_from_string(val, setting_name):
    """
    Attempt to import a class from a string representation.
    """
    try:
        return import_string(val)
    except ImportError as e:
        msg = "Could not import %r for setting %r. %s: %s." % (val, setting_name, e.__class__.__name__, e)
        raise ImportError(msg)


class ProviderSettings:
    """
    A setting object that allows provider settings to be accessed as properties.
    """

    def __init__(self, user_settings=None, defaults=None, import_strings=None, mandatory=None):
        self._user_settings = user_settings or {}
        self.defaults = defaults or DEFAULTS
        self.import_strings = import_strings or IMPORT_STRINGS
        self.mandatory = mandatory or ()

    @property
    def user_settings(self):
        if not hasattr(self, "_user_settings"):
            self._user_settings = getattr(settings, "AUTH_PROVIDER", {})
        return self._user_settings

    def __getattr__(self, attr):
        if attr not in self.defaults:
            raise AttributeError("Invalid Provider setting: %s" % attr)

        try:
            # check if present in user settings
            val = self._user_settings[attr]
        except KeyError:
            # Fall back to defaults
            val = self.defaults[attr]

        if val and attr in self.import_strings:
            val = perform_import(val, attr)
        self.validate_setting(attr, val)
        setattr(self, attr, val)
        return val

    def validate_setting(self, attr, val):
        if not val and attr in self.mandatory:
            raise AttributeError("OAuth2Provider setting: %s is mandatory" % attr)
        return self.defaults[attr]


auth_settings = ProviderSettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS, MANDATORY)
