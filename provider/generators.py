from oauthlib.common import UNICODE_ASCII_CHARACTER_SET
from oauthlib.common import generate_client_id as oauthlib_generate_client_id

from main.settings import auth_settings


class BaseHashGenerator:
    """
    All generators should extend this class overriding '.hash()' method
    """

    def hash(self):
        raise NotImplementedError()


class ClientIdGenerator(BaseHashGenerator):
    def hash(self):
        """
        Generate a client_id for Basic Authentication scheme
        """
        return oauthlib_generate_client_id(length=40, chars=UNICODE_ASCII_CHARACTER_SET)


class ClientSecretGenerator(BaseHashGenerator):
    def hash(self):
        """
        Generate a client secret key
        """
        length = auth_settings.CLIENT_SECRET_GENERATOR_LENGTH
        chars = UNICODE_ASCII_CHARACTER_SET
        return oauthlib_generate_client_id(length=length, chars=chars)


def generate_client_id():
    """
    Generate a client id
    """
    client_id_generator = auth_settings.CLIENT_ID_GENERATOR_CLASS()
    return client_id_generator.hash()


def generate_client_secret():
    """
    Generate a client secret key
    """
    client_secret_generator = auth_settings.CLIENT_SECRET_GENERATOR_CLASS()
    return client_secret_generator.hash()
