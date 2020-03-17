# Copyright (c) Startmail.com, 2020
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
# Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import json

from transip_rest_client.generic_rest_client import GenericRestClient
from transip_rest_client.transip_token import TransipToken, TransipTokenPrivateKeyFormatException, \
    TransipTokenGeneralException
from transip_rest_client.transip_rest_client_exceptions import TransipRestException, TransIPRestResponseException, \
    TransIPRestDomainNotFound, TransIPRestRecordNotFound, TransIPRestUnexpectedStatus
from transip_rest_client.__pkgmetadata__ import __version__

ALLOWED_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'SSHFP', 'TLSA', 'CAA']
ALLOWED_VERBS = ['get', 'post', 'patch', 'put', 'delete']
DEFAULT_API_URL = "https://api.transip.nl/v6"
DEFAULT_EXPIRE = 86400


class TransipRestprivatekeyException(Exception):
    """Raised when there is a problem with authentication
    """
    pass


class TransipRestClient(GenericRestClient):
    """Python abstraction of the TransIP Rest API

    General implementation considerations:

    - a get request returns a (possible nested) dict or list (can be empty)
    - a post/put/patch request will not return anything
    - exceptions will be raised if needed. Exceptions are based on TransipRestException
    - 'related resources' are discarded

    TransIP documentation: https://api.transip.nl/rest/docs.html
    """
    def __init__(self,
                 user: str,
                 rsaprivate_key: str,
                 base_url: str = DEFAULT_API_URL,
                 timeout: int = 10):
        """
        :param user: accountname for TransIP
        :type user: str
        :param rsaprivate_key: The (converted to) RSA Private key for this account
        :type rsaprivate_key: str
        :param base_url: URL to authenticate to. default https://api.transip.nl/v6
        :type base_url: str
        :param timeout: timeout for connection in seconds
        :type timeout: int

        :raise TransipRestprivatekeyException: when authentication does not succeed.

        |
        """

        try:
            self.token = TransipToken(login=user, RSAprivate_key=rsaprivate_key)
        except (TransipTokenPrivateKeyFormatException, TransipTokenGeneralException) as e:
            raise TransipRestprivatekeyException(e)
        super().__init__(base_url,
                         user=user,
                         timeout=timeout,
                         headers=self._transip_headers())
        self.rate_limit_limit = None
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

    def _transip_headers(self) -> dict:
        headers = {"Content-Type": "application/json",
                   "Authorization": f'Bearer {self.token}',
                   "User-Agent": f"TransIPPythonRestClient/{__version__}"}
        return headers

    def _update_bookkeeping(self, headers) -> None:
        """ expose the API limits to whom it may concern """
        self.rate_limit_limit = int(headers.get('X-Rate-Limit-Limit', '0'))
        self.rate_limit_remaining = int(headers.get('X-Rate-Limit-Remaining', '0'))
        self.rate_limit_reset = int(headers.get('X-Rate-Limit-Reset', '0'))

    def _request(self, relative_endpoint, verb, params, expected_http_codes=None) -> tuple:
        """perform the actual request by calling the correct function in the generic rest client superclass
        """
        endpoint = f'{self.base_url}{relative_endpoint}'
        super_func = {'get': super().get_request,
                      'post': super().post_request,
                      'patch': super().patch_request,
                      'delete': super().delete_request}
        if verb not in super_func.keys():
            raise TransipRestException('verb "{verb}" not allowed in _do_request')
        expected_http_codes = list(set(expected_http_codes + [401]))
        jsonstr, headers, statuscode = super_func[verb](endpoint=endpoint, params=params,
                                                        expected_http_codes=expected_http_codes,
                                                        extra_headers=self._transip_headers())
        self._update_bookkeeping(headers)

        if statuscode not in expected_http_codes or statuscode == 401:
            if statuscode == 401:
                errormsg = json.loads(jsonstr)['error']
                raise TransIPRestResponseException(statuscode=statuscode, errormsg=errormsg)
            if statuscode >= 400:
                returnederror = json.loads(jsonstr)['error']
                errorcontext = f"http-action: '{verb}' endpoint: '{relative_endpoint}'"
                errormsg = f'{returnederror} ; {errorcontext}'
                raise TransIPRestResponseException(statuscode=statuscode, errormsg=errormsg)
            else:
                raise TransIPRestUnexpectedStatus(statuscode=statuscode, errormsg='Unexpected http status')
        if jsonstr:
            return json.loads(jsonstr), statuscode
        else:
            return {}, statuscode

    def get_products(self) -> dict:
        """ Returns all available products currently offered by TransIP.

        TransIP documentation: https://api.transip.nl/rest/docs.html#general-products-get

        :rtype: dict
        :return:

            A dict with information about TransIP products and prices

            example::

                { 'bigStorage':
                  [ { 'description': 'St Disk 2000 GB',
                      'name': 'vol-storage-contr',
                      'price': 10,
                      'recurringPrice': 10},
                    { 'description': '2000 GB',
                      'name': 'vol-storage-addon-contr',
                      'price': 10}
                  ]
                }


        """
        request, http_code = self._request(relative_endpoint='/products', verb='get', params=None,
                                           expected_http_codes=[200, ])
        return request.get('products', {})

    def ping(self) -> str:
        """ A simple test resource to check everything is working

        :rtype: str
        :return:
            a string containing 'pong' when connection and authentication is working
        """
        request, http_code = self._request(relative_endpoint='/api-test', verb='get', params=None,
                                           expected_http_codes=[200, ])
        return request.get('ping', '')

    def get_domains(self) -> dict:
        """ Returns all domains present in this TransIP account

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-domains-get

        :rtype: str
        :return:
            A list of dicts, each list entry contains a dict with administrative details about a domain

            example::

                [ { 'authCode': 'V496K%3A7N',
                    'cancellationDate': None,
                    'cancellationStatus': None,
                    'hasActionRunning': False,
                    'isDnsOnly': False,
                    'isTransferLocked': False,
                    'isWhitelabel': False,
                    'name': 'example.com',
                    'registrationDate': '2019-12-10',
                    'renewalDate': '2020-12-10',
                    'supportsLocking': True,
                    'tags': ['mytag']}
                ]
        """
        request, http_code = self._request(relative_endpoint='/domains', verb='get', params=None,
                                           expected_http_codes=[200, ])
        return request.get('domains', [])

    def get_domain(self, domain: str = None) -> dict:
        """ Returns administrative information about a signle domain

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-domains-get-1

        :param domain: an existing DNS domain
        :type domain: str

        :rtype: dict
        :return:
            A dict with administrative details about the domain

            example::

                { 'authCode': 'V496K%3A7N',
                  'cancellationDate': None,
                  'cancellationStatus': None,
                  'hasActionRunning': False,
                  'isDnsOnly': False,
                  'isTransferLocked': False,
                  'isWhitelabel': False,
                  'name': 'example.com',
                  'registrationDate': '2019-12-10',
                  'renewalDate': '2020-12-10',
                  'supportsLocking': True,
                  'tags': ['mytag']
                }

        :raises TransIPRestDomainNotFound: when the domain is not found
        """
        if domain is None:
            return {}
        request, http_code = self._request(relative_endpoint=f'/domains/{domain}', verb='get', params=None,
                                           expected_http_codes=[200, 404])
        if http_code == 404:
            raise TransIPRestDomainNotFound(errormsg=f'domain {domain} not found', statuscode=http_code)
        return request.get('domain', {})

    def get_dns_entries(self, domain: str = None) -> list:
        """ Returns DNS records for a domain

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-dns-get

        :param domain: an existing DNS domain (e.g. 'example.com')
        :type domain: str

        :rtype: dict
        :returns:
            a list of dicts describing the DNS records in this zone

            example::

                [ {'content': '37.97.254.27',
                   'expire': '300',
                   'name': '@',
                   'type': 'A'},
                  { 'content': '2a01:7c8:3:1337::27',
                    'expire': '300',
                    'name': '@',
                    'type': 'AAAA'}
                ]

        :raises TransIPRestDomainNotFound: when the domain is not found
        """
        if domain is None:
            return []
        request, http_code = self._request(relative_endpoint=f'/domains/{domain}/dns', verb='get', params=None,
                                           expected_http_codes=[200, 404, 406])
        if http_code == 404:
            raise TransIPRestDomainNotFound(errormsg=f'domain {domain} not found', statuscode=http_code)
        return request.get('dnsEntries', [])

    def post_dns_entry(self,
                       domain: str = None,
                       name: str = None,
                       expire: int = DEFAULT_EXPIRE,
                       record_type: str = None,
                       content: str = None) -> None:
        """ Add a DNS record to an existing DNS zone

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-dns-post

        :param domain: an existing DNS domain (e.g. 'example.com')
        :type domain: str
        :param name: the name of the record (e.g. 'www')
        :type name: str
        :param expire: expiry in seconds for caching this record (e.g. 86400)
        :type expire: int
        :param record_type: a valid DNS type (e.g. 'A', 'AAAA', 'TXT')
        :type record_type: str
        :param content: valid content for this type of DNS record (e.g. '127.0.0.1' for an 'A'-type record)
        :type content: str

        :rtype: None

        :raise TransipRestException: not all required arguments are passed
        :raise TransipRestException: when an invalid type is passed
        """
        if domain is None or expire is None or name is None or record_type is None or content is None:
            raise TransipRestException('post_dns_entry called without all required parameters')
        if record_type not in ALLOWED_TYPES:
            raise TransipRestException(f'type {record_type} not allowed in call to post_dns_entry')
        body = {'dnsEntry': {'name': name,
                             'expire': expire,
                             'type': record_type,
                             'content': content}}
        request, http_code = self._request(relative_endpoint=f'/domains/{domain}/dns', verb='post', params=body,
                                           expected_http_codes=[201, 403, 404, 406])
        return

    def patch_dns_entry(self,
                        domain: str = None,
                        name: str = None,
                        expire: int = DEFAULT_EXPIRE,
                        record_type: str = None,
                        content: str = None) -> None:
        """ Update the content of a single DNS entry, identified by the name, expire, type attributes.

        When multiple or none of the current DNS entries matches, an exception will be thrown.

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-dns-patch

        :param domain: an existing DNS domain (e.g. 'example.com')
        :type domain: str
        :param name: the name of the record (e.g. 'www')
        :type name: str
        :param expire: expiry in seconds for caching this record (e.g. 86400)
        :type expire: int
        :param record_type: a valid DNS type (e.g. 'A', 'AAAA', 'TXT')
        :type record_type: str
        :param content: new content for this  DNS record (e.g. '127.0.0.1' for an 'A'-type record)
        :type content: str

        :rtype: None

        :raise: TransipRestException: not all required arguments are passed
        :raise: TransipRestException: when an invalid type is passed
        """
        if domain is None or expire is None or name is None or record_type is None or content is None:
            raise TransipRestException('patch_dns_entry called without all required parameters')
        if record_type not in ALLOWED_TYPES:
            raise TransipRestException(f'type {record_type} not allowed in call to patch_dns_entry')
        body = {'dnsEntry': {'name': name,
                             'expire': expire,
                             'type': record_type,
                             'content': content}}
        respone, http_code = self._request(relative_endpoint=f'/domains/{domain}/dns', verb='patch', params=body,
                                           expected_http_codes=[204, 403, 404, 406])
        if http_code == 404:
            raise TransIPRestRecordNotFound(errormsg=f'Record not found', statuscode=http_code)
        return

    def delete_dns_entry(self,
                         domain: str = None,
                         name: str = None,
                         expire: int = DEFAULT_EXPIRE,
                         record_type: str = None,
                         content: str = None) -> None:
        """ Remove a single DNS entry in an existing DNS zone

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-dns-delete

        :param domain: an existing DNS domain (e.g. 'example.com')
        :type domain: str
        :param name: the name of the record (e.g. 'www')
        :type name: str
        :param expire: expiry in seconds for caching this record (e.g. 86400)
        :type expire: int
        :param record_type: a valid DNS type (e.g. 'A', 'AAAA', 'TXT')
        :type record_type: str
        :param content: current content for this  DNS record
        :type content: str
        :rtype: None
        """
        if domain is None or expire is None or name is None or record_type is None or content is None:
            raise TransipRestException('delete_dns_entry called without all required parameters')
        if record_type not in ALLOWED_TYPES:
            raise TransipRestException(f'type {record_type} not allowed in call to delete_dns_entry')
        body = {'dnsEntry': {'name': name,
                             'expire': expire,
                             'type': record_type,
                             'content': content}}
        request, http_code = self._request(relative_endpoint=f'/domains/{domain}/dns', verb='delete', params=body,
                                           expected_http_codes=[204, 403, 404])
        if http_code == 404:
            transip_error = request.get('error', '')
            raise TransIPRestRecordNotFound(errormsg=f'Record not found: {transip_error} ', statuscode=http_code)
        return

    def get_dnssec(self, domain: str = None) -> dict:
        """lists all DNSSEC entries for a domain once set.

        Note: TransIP will not publish the details for domains that use the TransIP nameservers. This call will only
        return results for domains that are registered at Transip, but use non-TransIP DNS.

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-dnssec-get

        :param domain: an existing DNS domain (e.g. 'example.com')
        :type domain: str

        :rtype: dict
        :returns:
            A dictionary with the DNSSec settings for this domain
        """
        if domain is None:
            return {}
        request, http_code = self._request(relative_endpoint=f'/domains/{domain}/dnssec', verb='get', params=None,
                                           expected_http_codes=[200, 404, 406])
        if http_code == 404:
            raise TransIPRestDomainNotFound(errormsg=f'domain {domain} not found', statuscode=http_code)
        return request.get('dnsSecEntries', {})

    def get_nameservers(self, domain: str = None) -> list:
        """Lists nameservers for a domain

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-nameservers-get

        :param domain: a domain that is hosted by TransIP
        :type domain: str

        :rtype: list
        :returns:
            A list of dicts with information about the nameservers for this domain.

            **Note**: currently only the hostnames are returned for transip nameservers

            example::

                [{'hostname': 'ns0.transip.net',
                  'ipv4': '',
                  'ipv6': ''},
                 {'hostname': 'ns1.transip.nl',
                  'ipv4': '',
                  'ipv6': ''},
                 {'hostname': 'ns2.transip.eu',
                  'ipv4': '',
                  'ipv6': ''}]

        :raises TransIPRestDomainNotFound: when the domain is not found
        """
        if domain is None:
            return []
        request, http_code = self._request(relative_endpoint=f'/domains/{domain}/nameservers', verb='get', params=None,
                                           expected_http_codes=[200, 404, 406])
        if http_code == 404:
            raise TransIPRestDomainNotFound(errormsg=f'domain {domain} not found', statuscode=http_code)
        return request.get('nameservers', [])

    def get_domain_actions(self, domain: str = None) -> dict:
        """get current (administrative) actions on a domain

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-actions-get

        :param domain: an existing domain hosted by TransIP
        :type domain: str

        :rtype: dict
        :returns:
            A dict with the name of the action, a message and a boolean indicating the result

            example::

                {'name': 'changeNameservers',
                 'message': 'success',
                 'hasFailed': False }
        """
        if domain is None:
            return {}
        request, http_code = self._request(relative_endpoint=f'/domains/{domain}/actions', verb='get', params=None,
                                           expected_http_codes=[200, 404, 406])
        if http_code == 404:
            raise TransIPRestDomainNotFound(errormsg=f'domain {domain} not found', statuscode=http_code)
        return request.get('action', [])

    def get_domain_zone_file(self, domain: str = None) -> str:
        """get the zonefile (BIND format) as a signle string

        TransIP documentation: https://api.transip.nl/rest/docs.html#domains-zone-file-get

        :param domain: an existing domain hosted by TransIP
        :type domain: str

        :rtype: str
        :returns:
            A string with the zone file

        :raises:
        """
        if domain is None:
            return ''
        request, http_code = self._request(relative_endpoint=f'/domains/{domain}/zone-file', verb='get', params=None,
                                           expected_http_codes=[200, 404, 406])
        if http_code == 404:
            raise TransIPRestDomainNotFound(errormsg=f'domain {domain} not found', statuscode=http_code)
        return request.get('zoneFile', '')
