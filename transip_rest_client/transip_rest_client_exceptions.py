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

ERROR_DESCRIPTION = {
    400: ("Bad Request", "the API version or URL is invalid."),
    401: ("Unauthorized", "there is something wrong with your authentication"),
    403: ("Forbidden", "you don’t have the necessary permissions to perform an operation"),
    404: ("Not Found", "a resource was not found."),
    405: ("Method Not Allowed",	"you’re using an HTTP method on a resource which does not support it."),
    406: ("Not Acceptable", "one or more required parameters are missing in the request, or something else is wrong."),
    408: ("Request Timeout", "the request got a timeout."),
    409: ("Conflict", "modification is not permitted at the moment. E.g. when a VPS is locked."),
    422: ("Unprocessable Entity", "the input attributes are invalid, e.g. malformed JSON."),
    429: ("Too Many Request", "the rate limit is exceeded."),
    500: ("Internal Server Error", "there is a server-side error."),
    501: ("Not Implemented", "the endpoint is not implemented.")
}

class TransipRestException(Exception):
    pass


class TransIPRestResponseException(TransipRestException):
    def __init__(self, *args, statuscode: int = None, errormsg: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.status = statuscode
        self.name = ERROR_DESCRIPTION[statuscode][0]
        self.description = ERROR_DESCRIPTION[statuscode][1]
        self.errormsg = errormsg

    def __str__(self):
        return f'API error code {self.status} ({self.name}): {self.description} ; {self.errormsg}'

class TransIPRestUnexpectedStatus(TransIPRestResponseException):
    pass

class TransIPRestDomainNotFound(TransIPRestResponseException):
    pass

class TransIPRestRecordNotFound(TransIPRestResponseException):
    pass