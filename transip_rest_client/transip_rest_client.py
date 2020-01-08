import json

from .generic_rest_client import GenericRestClient
from .transip_token import TransipToken, TransipTokenPrivateKeyFormatException, TransipTokenGeneralException
from .transip_rest_client_exceptions import TransipRestException, TransIPRestResponseException

ALLOWED_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'SSHFP', 'TLSA', 'CAA']
ALLOWED_VERBS = ['get', 'post', 'patch', 'put', 'delete']
DEFAULT_API_URL = "https://api.transip.nl/v6"
DEFAULT_EXPIRE = 86400


class TransipRestprivatekeyException(Exception):
    pass


class TransipRestClient(GenericRestClient):
    """Python abstraction of the TransIP Rest API

    In general:
    - a get request returns a (possible nested) dict or list (can be empty)
    - a post/put/patch request will not return anything
    - exceptions will be raised if needed. Exceptions are based on TransipRestException

    TransIP documentation can be found at https://api.transip.nl/rest/docs.html
    """
    def __init__(self,
                 user: str,
                 RSAprivate_key: str,
                 base_url: str = DEFAULT_API_URL,
                 timeout: int = 10):
        try:
            self.token = TransipToken(login=user, RSAprivate_key=RSAprivate_key)
        except (TransipTokenPrivateKeyFormatException, TransipTokenGeneralException) as e:
            raise TransipRestprivatekeyException(e)
        super().__init__(base_url,
                         user=user,
                         timeout=timeout,
                         headers=self._transip_headers())
        self.rate_limit_limit = None
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

    def _transip_headers(self):
        headers = {"Content-Type": "application/json",
                   "Authorization": f'Bearer {self.token}',
                   "User-Agent": "TransIPPythonRestClient/0.1"}
        return headers

    def _update_bookkeeping(self, headers):
        """ expose the API limits to whom it may concern """
        self.rate_limit_limit = int(headers.get('X-Rate-Limit-Limit', '0'))
        self.rate_limit_remaining = int(headers.get('X-Rate-Limit-Remaining', '0'))
        self.rate_limit_reset = int(headers.get('X-Rate-Limit-Reset', '0'))

    def _request(self, relative_endpoint, verb, params, expected_http_codes=None) -> dict:
        endpoint = f'{self.base_url}{relative_endpoint}'
        super_func = {'get': super().get_request,
                      'post': super().post_request,
                      'patch': super().patch_request,
                      'delete': super().delete_request}
        if verb not in super_func.keys():
            raise TransipRestException('verb "{verb}" not allowed in _do_request')
        expected_http_codes = list(set(expected_http_codes + [401]))
        request_headers_status = super_func[verb](endpoint=endpoint, params=params,
                                                 expected_http_codes=expected_http_codes,
                                                 extra_headers=self._transip_headers())
        jsonstr = request_headers_status[0]
        headers = request_headers_status[1]
        statuscode = request_headers_status[2]
        self._update_bookkeeping(headers)
        if statuscode == 401:
            errormsg = json.loads(jsonstr)['error']
            raise TransIPRestResponseException(statuscode=statuscode, errormsg=errormsg)
        if statuscode >= 400:
            returnederror = json.loads(jsonstr)['error']
            errorcontext = f"http-action: '{verb}' endpoint: '{relative_endpoint}'"
            errormsg = f'{returnederror} ; {errorcontext}'
            raise TransIPRestResponseException(statuscode=statuscode, errormsg=errormsg)
        if jsonstr:
            return json.loads(jsonstr)
        else:
            return {}

    def get_products(self) -> dict:
        """ Returns all available products currently offered by TransIP.

        :returns:
            A dict with information about TransIP products and prices
            example:
                { 'bigStorage': [ { 'description': 'Big Storage Disk 2000 GB',
                                    'name': 'volume-storage-contract',
                                    'price': 10,
                                    'recurringPrice': 10},
                                  { 'description': '2000 GB extra Big Storage',
                                    'name': 'volume-storage-addon-contract',
                                    'price': 10}
                                 ]
                }

        https://api.transip.nl/rest/docs.html#general-products-get
        """
        request = self._request(relative_endpoint='/products', verb='get', params=None,
                                expected_http_codes=[200, ])
        return request.get('products', {})

    def ping(self) -> str:
        """ A simple test resource to check everything is working

        :returns:
            a string containing 'pong' when connection and authentication is working
        """
        request = self._request(relative_endpoint='/api-test', verb='get', params=None,
                                expected_http_codes=[200, ])
        return request.get('ping', '')

    def get_domains(self) -> dict:
        """ Returns all domains present in this TransIP account

        :returns:
            A list of dicts, each list entry contains a dict with administrative details about a domain
            example:
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

        https://api.transip.nl/rest/docs.html#domains-domains-get
        """
        request = self._request(relative_endpoint='/domains', verb='get', params=None,
                                expected_http_codes=[200, ])
        return request.get('domains', [])

    def get_domain(self, domain: str = None) -> dict:
        """ Returns administrative information about a signle domain

        :argument:
            domain: an existing DNS domain

        :returns:
            A dict with administrative details about the domain
            example:
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

        https://api.transip.nl/rest/docs.html#domains-domains-get-1
        """
        if domain is None:
            return {}
        request = self._request(relative_endpoint=f'/domains/{domain}', verb='get', params=None,
                                expected_http_codes=[200, 404])
        return request.get('domain', {})


    def get_dns_entries(self, domain: str = None) -> dict:
        """ Returns DNS records for a domain

        :argument:
            domain (str): an existing DNS domain (e.g. 'example.com')

        :returns:
            a list of dicts describing the DNS records in this zone
            example:
            [ {'content': '37.97.254.27',
               'expire': '300',
               'name': '@',
               'type': 'A'},
              { 'content': '2a01:7c8:3:1337::27',
                'expire': '300',
                'name': '@',
                'type': 'AAAA'}
            ]

        https://api.transip.nl/rest/docs.html#domains-dns-get
        """
        if domain is None:
            return {}
        request = self._request(relative_endpoint=f'/domains/{domain}/dns', verb='get', params=None,
                                expected_http_codes=[200, 404, 406])
        return request.get('dnsEntries', {})

    def post_dns_entry(self,
                       domain: str = None,
                       name: str = None,
                       expire: int = DEFAULT_EXPIRE,
                       type: str = None,
                       content: str = None) -> None:
        """ Add a DNS record to an existing DNS zone

        :argument:
            domain (str): an existing DNS domain (e.g. 'example.com')
            name (str): the name of the record (e.g. 'www')
            expire (int): expiry in seconds for caching this record (e.g. 86400)
            type (str): a valid DNS type (e.g. 'A', 'AAAA', 'TXT')
            content (str): valid content for this type of DNS record (e.g. '127.0.0.1' for an 'A'-type record)

        :raises:
            TransipRestException: not all required arguments are passed
            TransipRestException: when an invalid type is passed

        https://api.transip.nl/rest/docs.html#domains-dns-post
        """
        if domain is None or expire is None or name is None or type is None or content is None:
            raise TransipRestException('post_dns_entry called without all required parameters')
        if type not in ALLOWED_TYPES:
            raise TransipRestException(f'type {type} not allowed in call to post_dns_entry')
        body = {'dnsEntry': {'name': name,
                             'expire': expire,
                             'type': type,
                             'content': content}}
        self._request(relative_endpoint=f'/domains/{domain}/dns', verb='post', params=body,
                      expected_http_codes=[201, 403, 404, 406])
        return

    def patch_dns_entry(self,
                       domain: str = None,
                       name: str = None,
                       expire: int = DEFAULT_EXPIRE,
                       type: str = None,
                       content: str = None) -> None:
        """ Update the content of a single DNS entry, identified by the name, expire, type attributes.

        :argument:
            domain (str): an existing DNS domain (e.g. 'example.com')
            name (str): the name of the record (e.g. 'www')
            expire (int): expiry in seconds for caching this record (e.g. 86400)
            type (str): a valid DNS type (e.g. 'A', 'AAAA', 'TXT')
            content (str): new content for this  DNS record (e.g. '127.0.0.1' for an 'A'-type record)

        :raises:
            TransipRestException: not all required arguments are passed
            TransipRestException: when an invalid type is passed


        When multiple or none of the current DNS entries matches, an exception will be thrown.
        https://api.transip.nl/rest/docs.html#domains-dns-patch
        """
        if domain is None or expire is None or name is None or type is None or content is None:
            raise TransipRestException('patch_dns_entry called without all required parameters')
        if type not in ALLOWED_TYPES:
            raise TransipRestException(f'type {type} not allowed in call to patch_dns_entry')
        body = {'dnsEntry': {'name': name,
                             'expire': expire,
                             'type': type,
                             'content': content}}
        self._request(relative_endpoint=f'/domains/{domain}/dns', verb='patch', params=body,
                      expected_http_codes=[204, 403, 404, 406])
        return

    def delete_dns_entry(self,
                       domain: str = None,
                       name: str = None,
                       expire: int = DEFAULT_EXPIRE,
                       type: str = None,
                       content: str = None) -> None:
        """ Remove a single DNS entry in an existing DNS zone

        :argument:
            domain (str): an existing DNS domain (e.g. 'example.com')
            name (str): the name of the record (e.g. 'www')
            expire (int): expiry in seconds for caching this record (e.g. 86400)
            type (str): a valid DNS type (e.g. 'A', 'AAAA', 'TXT')
            content (str): current content for this  DNS record


        https://api.transip.nl/rest/docs.html#domains-dns-delete
        """
        if domain is None or expire is None or name is None or type is None or content is None:
            raise TransipRestException('delete_dns_entry called without all required parameters')
        if type not in ALLOWED_TYPES:
            raise TransipRestException(f'type {type} not allowed in call to delete_dns_entry')
        body = {'dnsEntry': {'name': name,
                             'expire': expire,
                             'type': type,
                             'content': content}}
        self._request(relative_endpoint=f'/domains/{domain}/dns', verb='delete', params=body,
                      expected_http_codes=[204, 403, 404])
        return
