import base64
import datetime
import json
import re
import requests
import textwrap
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

DEFAULT_AUTH_URL = 'https://api.transip.nl/v6/auth'
DEFAULT_EXPIRATION_TIME = '30 minutes'


class TransipTokenPrivateKeyFormatException(Exception):
    pass


class TransipTokenGeneralException(Exception):
    pass


class TransipToken(object):
    """A class to manage the needed token for the TransIP REST API.
    as documented on https://api.transip.nl/rest/docs.html#header-authentication
    """
    def __init__(self,
                 login: str,
                 RSAprivate_key: str,
                 global_key: bool = False,
                 read_only: bool = False,
                 label: str = '',
                 auth_url: str = DEFAULT_AUTH_URL):
        """
        Args:
            login: a login name for an existing TransIP account
            RSAprivate_key: a RSA (!) private key for this TransIP account (see _fix_token for check)
            global_key: setting for key (see TransIP documentation)
            read_only: setting for key (see TransIP documentation)
            label: label for key (see TransIP documentation)
            auth_url: TransIP URL to authenticate to
        """
        self.login = login
        self.private_key = self._fix_key(RSAprivate_key)
        self.global_key = global_key
        self.read_only = read_only
        self.label = label
        self.auth_url = auth_url
        self.expiration_time = DEFAULT_EXPIRATION_TIME  # since the format is not documented, we only use the default
        self.token = None
        self.token_date = None
        self.request_body = None

    def set_label(self, label: str):
        """Set a label. This will invalidate the existing token, so a new one will have to be generated
        Args:
            label: a string with the label
        """
        if self.label != label:
            self.label = label
            self.token = None

    def get_token(self):
        if not self._valid_token():
            self._create_token()
        return self.token

    def __repr__(self):
        return self.get_token()

    def invalidate(self):
        """enable outside world to invalidate the token so a new one will be generated next time"""
        self.token = None
        self.token_date = None

    def _create_token(self):
        body = self._create_request_body()
        headers = {'Content-Type': 'application/json',
                   'Signature': self.signature}
        try:
            response = requests.post(url=self.auth_url, data=body, headers=headers)
        except Exception as e:
            raise TransipTokenGeneralException(f'Error during request of token: {e}')
        try:
            self.token = response.json()['token']
            self.token_date = datetime.datetime.now()
        except Exception as e:
            raise TransipTokenGeneralException(f'TransIP API did not return expected token: {e}')

    def _valid_token(self):
        """check existence and age of token
        a token is valid until 25 minutes after creation. Since we do not know the format for specifying another
        duration that 30 minutes, this is hard-coded
        """
        return self.token is not None \
               and self.token_date is not None \
               and (datetime.datetime.now() - self.token_date).seconds < 1500

    def _create_request_body(self):
        request_body = {'login': self.login,
                        'nonce': uuid.uuid1().hex[:10],  # a random string
                        'read_only': self.read_only,
                        'expiration_time': self.expiration_time,
                        'label': self.label,
                        'global_key': self.global_key
                        }
        self.request_body_dict = request_body
        self.request_body_string = json.dumps(request_body)
        self._create_signature()
        return self.request_body_string

    def _create_signature(self):
        """ Uses the private key to sign the request body. """
        private_key = serialization.load_pem_private_key(
            str.encode(self.private_key),
            password=None,
            backend=default_backend())
        signature = private_key.sign(
            str.encode(self.request_body_string),
            padding.PKCS1v15(),
            hashes.SHA512())
        self.signature = base64.b64encode(signature)

    @classmethod
    def _fix_key(cls, key):
        """
        Fix the format of the RSA private key
        make sure whitespace errors are fixed
        a private key should look like:

        -----BEGIN RSA PRIVATE KEY-----\n
        <lines of max64 characters>\n
        -----END RSA PRIVATE KEY-----

        NOTE: this code needs a RSA private key! A TransIP key has to be converted using
        openssl rsa -in private_key.pem
        """
        regexp = '-----BEGIN RSA PRIVATE KEY-----(.*)-----END RSA PRIVATE KEY-----'
        match = re.search(regexp, key, re.MULTILINE | re.DOTALL)
        if not match:
            raise TransipTokenPrivateKeyFormatException
        keybody = match.group(1)
        keybody = re.sub(' ', '', keybody)
        keybodylines = textwrap.wrap(keybody, 64)
        newkeybody = '\n'.join(keybodylines)
        return f'-----BEGIN RSA PRIVATE KEY-----\n{newkeybody}\n-----END RSA PRIVATE KEY-----'
