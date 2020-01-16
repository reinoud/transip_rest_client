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

from unittest import TestCase, skip

try:
    from transip_rest_client.tests.auth_setup import transipaccount, testdomain, RSAkey
except ImportError:
    print("missing authentication file needed to run tests")
    print("please create a file called 'auth_setup.py' in the tests directory")
    print("defining 3 variables like this:")
    print("transipaccount = 'my-account-name'")
    print("RSAkey = '-----BEGIN RSA PRIVATE KEY-----\n<generated RSA private key for Rest API>\n-----END RSA PRIVATE KEY-----'")
    print("testdomain = 'mydomain.com'")
    print("the testaccount should have at least 1 domain, DNS entries will be changed in this domain during tests!")
    exit(1)

from transip_rest_client.tests.utils_for_test import random_string
from transip_rest_client.transip_token import TransipToken, TransipTokenPrivateKeyFormatException


class TestTransipToken(TestCase):
    def setUp(self) -> None:
        self.token = TransipToken(login=transipaccount, RSAprivate_key=RSAkey)

    def test_set_label(self):
        oldlabel = self.token._label
        oldtoken = self.token.get_token()
        while True:
            newlabel = random_string()
            if newlabel != oldlabel:
                break
        self.token.set_label(newlabel)
        new_returned_label = self.token._label
        newtoken = self.token.get_token()
        self.assertEqual(new_returned_label, newlabel,
                         msg="expected the set label being equal to the returned label")
        self.assertNotEqual(oldtoken, newtoken,
                            msg="expected new token after setting new label")

    def test_get_token(self):
        token = self.token.get_token()
        self.assertIsInstance(token, str,
                              msg="expected returned token to be a string")
        self.assertGreater(len(token), 1,
                           msg="expected a token longer than 1")

    def test_invalidate(self):
        oldtoken = self.token.get_token()
        self.token.invalidate()
        newtoken = self.token.get_token()
        self.assertNotEqual(oldtoken, newtoken,
                            msg="expeted a new token after previous one was invalidated")