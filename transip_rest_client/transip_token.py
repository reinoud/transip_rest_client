# Copyright (c) Startmail.com, 2020
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
# Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

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


class TransipTokenAuthorisationException(Exception):
    """Raised when authorisation at TransIP fails. Usually this means that there is something wrong with the used
    private key (is it converted to RSA?). Whitelisting problems raise another exception.
    """
    pass


class TransipTokenPrivateKeyFormatException(Exception):
    """Raised when the supplied private key does not look correct
    """
    pass


class TransipTokenGeneralException(Exception):
    """Raised when something is wrong during the request of a token. There should be more information in the content
    of the exception
    """
    pass


class TransipToken(object):
    """A class to manage the needed token for the TransIP REST API.
    as documented on https://api.transip.nl/rest/docs.html#header-authentication

    The steps taken are:

    - create a request body (including a random 'nonce' field and label(s))
    - create a signature by encrypting this request body with the private key
    - send a request to the auth endpoint with the request body and signature
      (this proves that we have the private key since TransIP can decrypt it with the public key)
    - a token is sent back to us by TransIP that can be used until it expires

    |
    """
    def __init__(self,
                 login: str,
                 RSAprivate_key: str,
                 global_key: bool = False,
                 read_only: bool = False,
                 label: str = '',
                 auth_url: str = DEFAULT_AUTH_URL):
        """
        :param login: a login name for an existing TransIP account
        :type login: str
        :param RSAprivate_key: a RSA (!) private key for this TransIP account (see _fix_token for check)
        :type RSAprivate_key: str
        :param global_key: setting for key (see TransIP documentation)
        :type global_key: bool
        :param read_only: setting for key (see TransIP documentation)
        :type read_only: bool
        :param label: label(s) for key (see TransIP documentation), concatenate with comma's ("label1,label2")
        :type label: str
        :param auth_url: TransIP URL to authenticate to
        :type auth_url: str

        |
        """
        self._login = login
        self._private_key = self._fix_key(RSAprivate_key)
        self._global_key = global_key
        self._read_only = read_only
        self._label = label
        self._auth_url = auth_url
        self._expiration_time = DEFAULT_EXPIRATION_TIME  # since the format is not documented, we only use the default
        self._token = None
        self._token_date = None
        self._request_body = None

    def set_label(self, label: str):
        """Set label(s). This will invalidate the existing token, so a new one will have to be generated

        :param label: a string with the label(s) (separated by comma's: "label1,label2")
        :type label: str
        """
        if self._label != label:
            self._label = label
            self._token = None

    def get_token(self):
        """Return the current token; create one when there is none"""
        if not self._valid_token():
            self._create_token()
        return self._token

    def __repr__(self):
        return self.get_token()

    def invalidate(self):
        """enable outside world to invalidate the token so a new one will be generated next time"""
        self._token = None
        self._token_date = None

    def _create_token(self):
        body = self._create_request_body()
        headers = {'Content-Type': 'application/json',
                   'Signature': self.signature}
        try:
            response = requests.post(url=self._auth_url, data=body, headers=headers)
        except Exception as e:
            raise TransipTokenGeneralException(f'Error during request of token: {e}')
        if response.status_code == 401:
            errorreason = json.loads(response.content)['error']
            raise TransipTokenAuthorisationException(f'Error with authentication: {errorreason}, please check private key')
        try:
            self._token = response.json()['token']
            self._token_date = datetime.datetime.now()
        except Exception as e:
            raise TransipTokenGeneralException(f'TransIP API did not return expected token: {e}')

    def _valid_token(self):
        """check existence and age of token
        a token is valid until 25 minutes after creation. Since we do not know the format for specifying another
        duration that 30 minutes, this is hard-coded
        """
        return self._token is not None \
               and self._token_date is not None \
               and (datetime.datetime.now() - self._token_date).seconds < 1500

    def _create_request_body(self):
        request_body = {'login': self._login,
                        'nonce': uuid.uuid4().hex[:10],  # a random string
                        'read_only': self._read_only,
                        'expiration_time': self._expiration_time,
                        'label': self._label,
                        'global_key': self._global_key
                        }
        self.request_body_dict = request_body
        self.request_body_string = json.dumps(request_body)
        self._create_signature()
        return self.request_body_string

    def _create_signature(self):
        """ Uses the private key to sign the request body. """
        private_key = serialization.load_pem_private_key(
            str.encode(self._private_key),
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
