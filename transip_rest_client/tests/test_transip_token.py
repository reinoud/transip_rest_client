from unittest import TestCase

try:
    from auth_setup import transipaccount, testdomain, RSAkey
except:
    print("missing authentication file needed to run tests")
    print("please create a file called 'auth_setup.py' in the tests directory")
    print("defining 3 variables like this:")
    print("transipaccount = 'my-account-name'")
    print("RSAkey = '-----BEGIN RSA PRIVATE KEY-----\n<generated RSA private key for Rest API>\n-----END RSA PRIVATE KEY-----'")
    print("testdomain = 'mydomain.com'")
    print("the testaccount should have at least 1 domain, DNS entries will be changed in this domain during tests!")
    exit(1)

from utils_for_test import random_string
from transip_rest_client.transip_token import TransipToken, TransipTokenPrivateKeyFormatException

class TestTransipToken(TestCase):
    def setUp(self) -> None:
        self.token = TransipToken(login=transipaccount, RSAprivate_key=RSAkey)
        pass

    def test_set_label(self):
        oldlabel = self.token.label
        while True:
            newlabel = random_string()
            if newlabel != oldlabel:
                break
        self.token.set_label(newlabel)
        new_returned_label = self.token.label
        self.assertEqual(new_returned_label, newlabel,
                         msg="expected the set label being equal to the returned label")

    def test_get_token(self):
        token = self.token.get_token()
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 1)

    def test_invalidate(self):
        token = self.token.get_token()
        self.token.invalidate()
        newtoken = self.token.get_token()
        self.assertNotEqual(token, newtoken)
