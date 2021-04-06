from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

AUTH_PROVIDER = {
    "CLIENT_ID_GENERATOR_CLASS": "provider.generators.ClientIdGenerator",
    "CLIENT_SECRET_GENERATOR_CLASS": "provider.generators.ClientSecretGenerator"
}

USER_SETTINGS = getattr(settings, 'AUTH_PROVIDER', None)

APPLICATION_MODEL = getattr(settings, "PROVIDER_APPLICATION_MODEL", "provider.Application")
ACCESS_TOKEN_MODEL = getattr(settings, "PROVIDER_ACCESS_TOKEN_MODEL", "provider.AccessToken")
ID_TOKEN_MODEL = getattr(settings, "PROVIDER_ID_TOKEN_MODEL", "provider.IDToken")
GRANT_MODEL = getattr(settings, "PROVIDER_GRANT_MODEL", "provider.Grant")
REFRESH_TOKEN_MODEL = getattr(settings, "PROVIDER_REFRESH_TOKEN_MODEL", "provider.RefreshToken")

DEFAULTS = {
    "CLIENT_ID_GENERATOR_CLASS": "provider.generators.ClientIdGenerator",
    "CLIENT_SECRET_GENERATOR_CLASS": "provider.generators.ClientSecretGenerator",
    "CLIENT_SECRET_GENERATOR_LENGTH": 128,
    "APPLICATION_MODEL": APPLICATION_MODEL,
    "ACCESS_TOKEN_MODEL": ACCESS_TOKEN_MODEL,
    "REFRESH_TOKEN_MODEL": REFRESH_TOKEN_MODEL,
    "GRANT_MODEL": GRANT_MODEL,
    "ID_TOKEN_MODEL": ID_TOKEN_MODEL,
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": 60,
    "ACCESS_TOKEN_EXPIRE_SECONDS": 3600,
    "ID_TOKEN_EXPIRE_SECONDS": 3600,
    "REFRESH_TOKEN_EXPIRE_SECONDS": None,
    "ALLOWED_REDIRECT_URI_SCHEMES": ["http", "https"],
    "SCOPES": {"read": "Reading scope", "write": "Writing scope"},
    "DEFAULT_SCOPES": ["__all__"],
    "SCOPES_BACKEND_CLASS": "provider.scopes.SettingsScopes",
    "_SCOPES": [],
    "_DEFAULT_SCOPES": [],
    "EXTRA_SERVER_KWARGS": {},
    "OAUTH2_SERVER_CLASS": "oauthlib.oauth2.Server",
    "OAUTH2_VALIDATOR_CLASS": "provider.auth_validators.OAuth2Validator",
    "OAUTH2_BACKEND_CLASS": "provider.auth_backends.OAuthLibCore",
    "ACCESS_TOKEN_GENERATOR": None,
    "REFRESH_TOKEN_GENERATOR": None,
    "PKCE_REQUIRED": False,
    "ROTATE_REFRESH_TOKEN": True,
    "RESOURCE_SERVER_INTROSPECTION_URL": None,
    "RESOURCE_SERVER_AUTH_TOKEN": None,
    "RESOURCE_SERVER_INTROSPECTION_CREDENTIALS": None,
    "REFRESH_TOKEN_GRACE_PERIOD_SECONDS": 0,
}

IMPORT_STRINGS = (
    "CLIENT_ID_GENERATOR_CLASS",
    "CLIENT_SECRET_GENERATOR_CLASS",
    "OAUTH2_SERVER_CLASS",
    "OAUTH2_BACKEND_CLASS",
    "OAUTH2_VALIDATOR_CLASS",
    "ACCESS_TOKEN_GENERATOR",
    "REFRESH_TOKEN_GENERATOR",
    "SCOPES_BACKEND_CLASS"
)

MANDATORY = (
    "CLIENT_ID_GENERATOR_CLASS",
    "CLIENT_SECRET_GENERATOR_CLASS",
    "OAUTH2_SERVER_CLASS",
    "SCOPES",
    "OAUTH2_BACKEND_CLASS",
    "OAUTH2_VALIDATOR_CLASS",
    "ALLOWED_REDIRECT_URI_SCHEMES",
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

        # Overriding special settings
        if attr == "_SCOPES":
            val = list(self.SCOPES.keys())
        if attr == "_DEFAULT_SCOPES":
            if "__all__" in self.DEFAULT_SCOPES:
                val = list(self._SCOPES)
            else:
                val = []
                for scope in self.DEFAULT_SCOPES:
                    if scope in self._SCOPES:
                        val.append(scope)
                    else:
                        raise ImproperlyConfigured("Defined DEFAULT_SCOPES not present in SCOPES")
        self.validate_setting(attr, val)
        setattr(self, attr, val)
        return val

    def validate_setting(self, attr, val):
        if not val and attr in self.mandatory:
            raise AttributeError("OAuth2Provider setting: %s is mandatory" % attr)
        return self.defaults[attr]

    @property
    def server_kwargs(self):
        """
        This is used to communicate settings to oauth server.
        Takes relevant settings and format them accordingly.
        There's also EXTRA_SERVER_KWARGS that can override every value
        and is more flexible regarding keys and acceptable values
        but doesn't have import string magic or any additional
        processing, callables have to be assigned directly.
        For the likes of signed_token_generator it means something like
        {"token_generator": signed_token_generator(privkey, **kwargs)}
        """
        kwargs = {
            key: getattr(self, value)
            for key, value in [
                ("token_expires_in", "ACCESS_TOKEN_EXPIRE_SECONDS"),
                ("refresh_token_expires_in", "REFRESH_TOKEN_EXPIRE_SECONDS"),
                ("token_generator", "ACCESS_TOKEN_GENERATOR"),
                ("refresh_token_generator", "REFRESH_TOKEN_GENERATOR"),
            ]
        }
        kwargs.update(self.EXTRA_SERVER_KWARGS)
        return kwargs


auth_settings = ProviderSettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS, MANDATORY)
