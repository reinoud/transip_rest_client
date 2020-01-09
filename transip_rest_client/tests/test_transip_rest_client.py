from unittest import TestCase, expectedFailure
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
from transip_rest_client import TransipRestClient, TransIPRestResponseException, TransipTokenAuthorisationException


class TestTransipRestClient(TestCase):
    def setUp(self) -> None:
        self.transip_client = TransipRestClient(user=transipaccount, RSAprivate_key=RSAkey)
        return

    def test_ping(self):
        answer = self.transip_client.ping()
        self.assertEqual(answer, 'pong')

    def test__transip_headers(self):
        headers = self.transip_client._transip_headers()
        self.assertIsInstance(headers, dict,
                              msg="TransIPRestclient._transip_haders expected dict")
        self.assertIsNotNone(headers['Authorization'],
                          msg="Expected Authorisation in TransIPRestclient._transip_haders")
        self.assertEqual(len(headers), 3,
                         msg="exepected 3 headers in TransIPRestclient._transip_haders")

    def test__update_bookkeeping(self):
        self.transip_client.get_products()
        oldcounter = self.transip_client.rate_limit_remaining
        self.transip_client.get_products()
        newcounter = self.transip_client.rate_limit_remaining
        self.assertLess(newcounter, oldcounter,
                        msg="expected rate_limit_remaining to go down")
        self.assertGreater(self.transip_client.rate_limit_limit, 0,
                           msg="expected a limit > 0")

    def test_get_products(self):
        products = self.transip_client.get_products()
        self.assertIsInstance(products, dict,
                              msg="expected a dict when calling get_products")
        self.assertGreater(len(products), 1,
                           msg="expected more than 1 product when calling get_products")

    def test_get_domains(self):
        domains = self.transip_client.get_domains()
        domainnames = [x['name'] for x in domains]
        self.assertIsInstance(domains, list,
                              msg="expected a list when calling get_domains")
        self.assertGreater(len(domains), 0,
                           msg="expected more than 0 domains when calling get_domains")
        self.assertIn(testdomain, domainnames,
                      msg=f"expected domain {testdomain} to be present when calling get_domains")

    def test_get_domain(self):
        domain = self.transip_client.get_domain(testdomain)
        self.assertIsInstance(domain, dict,
                              msg="expected a dict when calling get_domain")
        self.assertEqual(testdomain, domain['name'],
                         msg=f"expected domain {testdomain} when calling get_domain({testdomain})")

    def test_get_dns_entries(self):
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        self.assertIsInstance(dns_entries, list,
                              msg="exepected a list when calling get_dns_entries")
        if len(dns_entries) > 0:
            from transip_rest_client.transip_rest_client import ALLOWED_TYPES
            allowed_types_string = ', '.join([f'"{x}"' for x in ALLOWED_TYPES])
            self.assertIn(dns_entries[0]['type'], ALLOWED_TYPES,
                          msg=f"expected {dns_entries[0]['type']} to be of allowed type ({allowed_types_string})")

    def test_post_patch_delete_dns_entry(self):
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        hostnames = [x['name'] for x in dns_entries]
        # pick a hostname that is not present yet
        while True:
            hostname = random_string()
            if hostname not in hostnames:
                break

        self.transip_client.post_dns_entry(domain=testdomain, name=hostname, expire=84600, type='A', content='1.2.3.4')
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        hostnames = [x['name'] for x in dns_entries]
        self.assertIn(hostname, hostnames,
                      msg=f"expected hostname {hostname} to be present after successfull post_dns_entry")

        with self.assertRaises(TransIPRestResponseException,
                               msg="expected exception TransIPRestResponseException when patching a non-existing record"):
            self.transip_client.patch_dns_entry(domain=testdomain, name=hostname, expire=84600, type='TXT',
                                                content='1.2.3.5')

        self.transip_client.patch_dns_entry(domain=testdomain, name=hostname, expire=84600, type='A', content='1.2.3.5')
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        hostentry = [d for d in dns_entries if d['name'] == hostname][0]
        self.assertEqual(hostentry['content'], '1.2.3.5',
                         msg=f"expected content to be '1.2.3.5' after patching hostname {hostname}")

        with self.assertRaises(TransIPRestResponseException,
                               msg="expected exception TransIPRestResponseException when patching a non-existing record"):
            self.transip_client.delete_dns_entry(domain=testdomain, name=hostname, expire=84600, type='TXT',
                                                 content='1.2.3.5')

        self.transip_client.delete_dns_entry(domain=testdomain, name=hostname, expire=84600, type='A', content='1.2.3.5')
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        hostnames = [x['name'] for x in dns_entries]
        self.assertNotIn(hostname, hostnames,
                         msg="expected hostname to be deleted after calling delete_dns_entry")

    def test_invalidkey(self):
        wrongkey = RSAkey[:50] + random_string() + RSAkey[60:]
        with self.assertRaises(TransipTokenAuthorisationException):
            non_authorizing_transip_client = TransipRestClient(user=transipaccount, RSAprivate_key=wrongkey)

