import logging
import requests
from urllib.parse import urljoin


class RequestFailureException(Exception):
    """Raised when the request did *not* succeed, and we know nothing happened
    in the remote side. From a businness-logic point of view, the operation the
    client was supposed to perform did NOT happen"""

    def __init__(self, *args, url='', response=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = response
        self.url = url


class UnknownResultException(Exception):
    """Raised when we don't know if the request was completed or not. From a
    businness-logic point of view, it is not known if the operation succeded,
    or failed"""

    def __init__(self, *args, url='', response=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = response
        self.url = url


class UnknownVerbException(Exception):

    """Raised when a unknown verb is used for a request"""
    pass


logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "Content-Type": "application/json",
}

requestfunction = {
    'DELETE': requests.delete,
    'GET': requests.get,
    'HEAD': requests.head,
    'OPTIONS': requests.options,
    'PATCH': requests.patch,
    'POST': requests.post,
    'PUT': requests.put,
}


class GenericRestClient:
    def __init__(self,
                 base_url: str,
                 user: str,
                 timeout: int = 10,
                 headers: dict = None):
        self.base_url = base_url
        self.user = user
        self.timeout = timeout
        if headers is None:
            headers = DEFAULT_HEADERS
        self.headers = headers

    def _do_request(self,
                    endpoint:str,
                    params:dict,
                    call_type:str,
                    expected_http_codes:list=None,
                    extra_headers:dict=None):
        """Create a payload and send a new post request to the url given
        Args:
            endpoint (string): portion of the endpoint for the service
            params (dict): a valid data object
            call_type (string): one of "get" or "post"
            expected_http_codes list(int): expected codes for the request
            extra_headers (dict): extra headers needed
        Raises:
            RequestFailureException
            UnknownResultException
            UnknownVerbException
        Returns:
            The response offered by the requests library when using get or post
        """
        if expected_http_codes is None:
            expected_http_codes = [200]
        if extra_headers is None:
            extra_headers = {}
        url = urljoin(self.base_url, endpoint)
        call_headers = self.headers.update(extra_headers)
        try:
            # blah = requests.get    (url, params,kwargs)
            # blah = requests.post   (url, data,json,kwargs)
            # blah = requests.patch  (url, data, kwargs)
            #bla = requests.pa
            # blah = requests.put    (url, data, kwargs)
            # blah = requests.options(url, kwargs)
            # blah = requests.delete (url, kwargs)
            # blah = requests.head   (url,kwargs)

            # this seems like an ugly construct, but some of the calls have slightly different parameters so this
            # is hard to generalize.
            if call_type == 'get':
                response = requests.get(
                    url,
                    params=params,
                    headers=self.headers,
                    timeout=self.timeout,
                )
            elif call_type == 'post':
                response = requests.post(
                    url,
                    json=params,
                    headers=self.headers,
                    timeout=self.timeout,
                )
            elif call_type == 'put':
                response = requests.put(
                    url,
                    json=params,
                    headers=self.headers,
                    timeout=self.timeout,
                )
            elif call_type == 'patch':
                response = requests.patch(
                    url,
                    json=params,
                    headers=self.headers,
                    timeout=self.timeout,
                )
            elif call_type == 'delete':
                response = requests.delete(
                    url,
                    json=params,
                    headers=self.headers,
                    timeout=self.timeout,
                )
            else:
                logger.error(f'GenericRestClient._do_request called with unknown verb {call_type}')
                raise UnknownVerbException(call_type)
        except requests.exceptions.ConnectionError as exc:
            logger.error(
                'Could not connect to API',
                extra={
                    'url': url,
                    'request_body': params,
                    'timeout': self.timeout,
                    'exception': exc,
                },
            )
            raise RequestFailureException(url=url) from exc
        except requests.exceptions.Timeout as exc:
            logger.error(
                'Timeout in request to API',
                extra={
                    'url': url,
                    'request_body': params,
                    'timeout': self.timeout,
                    'exception': exc,
                },
            )
            raise UnknownResultException(url=url) from exc

        if response.status_code in expected_http_codes:
            return response.content, response.headers, response.status_code

        if response.status_code == 401:
            errmsg = response.content
            raise RequestFailureException(errmsg)
        if 401 < response.status_code < 500:
            errmsg = 'API returned HTTP 4xx error'

            logger.error(errmsg, extra={
                'url': url,
                'request_body': params,
                'response_status_code': response.status_code,
                'response_body': response.content,
            })
            raise RequestFailureException(url=url, response=response)

        if response.status_code >= 500:
            logger.error('API REST returned HTTP 5xx error', extra={
                'url': url,
                'request_body': params,
                'response_status_code': response.status_code,
                'response_body': response.content,
            })
            raise UnknownResultException(
                url=url, response=response,
            )

        logger.error(
            'Unexpected status code in response from API',
            extra={
                'url': url,
                'request_body': params,
                'response_status_code': response.status_code,
                'response_body': response.content,
            }
        )

        raise RequestFailureException(
            url=url, response=response,
        )

    def get_request(self,
                    endpoint: str,
                    params: dict,
                    expected_http_codes: list = None,
                    extra_headers: dict = None):
        """Create a payload and send a new post request to the given url

        Args:
            endpoint (string): portion of the endpoint for the service
            params (dict): a valid data object
            expected_http_codes list(int): expected codes for the request
        Returns:
            The response offered by the requests library when using get
        """
        return self._do_request(endpoint, params, 'get', expected_http_codes, extra_headers)

    def post_request(self,
                     endpoint: str,
                     params: dict,
                     expected_http_codes: list = None,
                     extra_headers: dict = None):
        """Create a payload and send a new post request to the given url

        Args:
            endpoint (string): portion of the endpoint for the service
            params (dict): a valid data object
            expected_http_codes list(int): expected codes for the request
        Returns:
            The response offered by the requests library when using post
        """
        return self._do_request(
            endpoint,
            params,
            'post',
            expected_http_codes,
            extra_headers,
        )

    def put_request(self, endpoint, params, expected_http_codes=None, extra_headers=None):
        """Sends a request to update an element

        Args:
            endpoint (string): name of the service
            params (dict): information to be updated
            expected_http_codes list(int): expected codes for the request
        Returns:
            The response offered by the requests library when using post
        """
        return self._do_request(
            endpoint,
            params,
            'put',
            expected_http_codes,
            extra_headers,
        )

    def patch_request(self, endpoint, params, expected_http_codes=None, extra_headers=None):
        """Sends a request to partially update an element

        Args:
            endpoint (string): name of the service
            params (dict): information to be updated
            expected_http_codes list(int): expected codes for the request
        Returns:
            The response offered by the requests library when using post
        """
        return self._do_request(
            endpoint,
            params,
            'patch',
            expected_http_codes,
            extra_headers,
        )

    def delete_request(self, endpoint, params, expected_http_codes=None, extra_headers=None):
        """Sends a request to partially update an element

        Args:
            endpoint (string): name of the service
            params (dict): information to be updated
            expected_http_codes list(int): expected codes for the request
        Returns:
            The response offered by the requests library when using post
        """
        return self._do_request(
            endpoint,
            params,
            'delete',
            expected_http_codes,
            extra_headers,
        )

# TODO: head_request
# TODO: options_request
