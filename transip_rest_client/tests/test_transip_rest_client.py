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

from unittest import TestCase, expectedFailure
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
from transip_rest_client import TransipRestClient, TransipTokenAuthorisationException, \
    TransIPRestDomainNotFound, TransIPRestRecordNotFound, TransipTokenGeneralException, TransipRestException
from transip_rest_client.generic_rest_client import UnknownResultException


class TestTransipRestClient(TestCase):
    def setUp(self) -> None:
        self.transip_client = TransipRestClient(user=transipaccount, rsaprivate_key=RSAkey)

    def test_ping(self):
        answer = self.transip_client.ping()
        self.assertEqual(answer, 'pong')

    def test_wrong_key(self):
        middle_of_key = len(RSAkey) // 2
        wrongkey = RSAkey[:middle_of_key] + random_string() + RSAkey[middle_of_key:]
        with self.assertRaises(TransipTokenGeneralException):
            failing_client = TransipRestClient(user=transipaccount, rsaprivate_key=wrongkey)

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
        empty_domain = self.transip_client.get_domain('')
        self.assertIsInstance(empty_domain, dict,
                              msg="expected a dict when calling get_domain")
        self.assertEqual(len(empty_domain), 0,
                         msg=f"expected empty dict when calling get_domain with empty string")
        empty_domain = self.transip_client.get_domain(None)
        self.assertIsInstance(empty_domain, dict,
                              msg="expected a dict when calling get_domain")
        self.assertEqual(len(empty_domain), 0,
                         msg=f"expected empty dict when calling get_domain with None as domain")
        with self.assertRaises(TransIPRestDomainNotFound):
            self.transip_client.get_domain(testdomain + '.invalidtld')

    def test_get_dns_entries(self):
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        self.assertIsInstance(dns_entries, list,
                              msg="exepected a list when calling get_dns_entries")
        if len(dns_entries) > 0:
            from transip_rest_client.transip_rest_client import ALLOWED_TYPES
            allowed_types_string = ', '.join([f'"{x}"' for x in ALLOWED_TYPES])
            self.assertIn(dns_entries[0]['type'], ALLOWED_TYPES,
                          msg=f"expected {dns_entries[0]['type']} to be of allowed type ({allowed_types_string})")

        dns_entries = self.transip_client.get_dns_entries('')
        self.assertIsInstance(dns_entries, list,
                              msg="exepected a list when calling get_dns_entries")
        self.assertEqual(len(dns_entries), 0,
                         msg=f"expected empty dict when calling get_dns_entries with empty string")

        dns_entries = self.transip_client.get_dns_entries(None)
        self.assertIsInstance(dns_entries, list,
                              msg="exepected a list when calling get_dns_entries")
        self.assertEqual(len(dns_entries), 0,
                         msg=f"expected empty dict when calling get_dns_entries with None as domain")

        with self.assertRaises(TransIPRestDomainNotFound):
            self.transip_client.get_dns_entries(testdomain + '.invalidtld')

    def test_post_patch_delete_dns_entry(self):
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        hostnames = [x['name'] for x in dns_entries]
        # pick a hostname that is not present yet
        while True:
            hostname = random_string()
            if hostname not in hostnames:
                break

        # post new record
        self.transip_client.post_dns_entry(domain=testdomain, name=hostname, expire=84600, record_type='A',
                                           content='1.2.3.4')
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        hostnames = [x['name'] for x in dns_entries]
        self.assertIn(hostname, hostnames,
                      msg=f"expected hostname {hostname} to be present after successfull post_dns_entry")

        with self.assertRaises(TransIPRestRecordNotFound,
                               msg="expected exception TransIPRestRecordNotFound when patching a non-existing record"):
            self.transip_client.patch_dns_entry(domain=testdomain, name=hostname, expire=84600, record_type='TXT',
                                                content='1.2.3.5')

        self.transip_client.patch_dns_entry(domain=testdomain, name=hostname, expire=84600, record_type='A',
                                            content='1.2.3.5')
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        hostentry = [d for d in dns_entries if d['name'] == hostname][0]
        self.assertEqual(hostentry['content'], '1.2.3.5',
                         msg=f"expected content to be '1.2.3.5' after patching hostname {hostname}")

        with self.assertRaises(TransIPRestRecordNotFound,
                               msg="expected exception TransIPRestRecordNotFound when patching a non-existing record"):
            self.transip_client.delete_dns_entry(domain=testdomain, name=hostname, expire=84600, record_type='TXT',
                                                 content='1.2.3.5')

        self.transip_client.delete_dns_entry(domain=testdomain, name=hostname, expire=84600, record_type='A',
                                             content='1.2.3.5')
        dns_entries = self.transip_client.get_dns_entries(testdomain)
        hostnames = [x['name'] for x in dns_entries]
        self.assertNotIn(hostname, hostnames,
                         msg="expected hostname to be deleted after calling delete_dns_entry")

    def test_dns_entry_wrong_call(self):
        with self.assertRaises(TransipRestException):
            self.transip_client.post_dns_entry(domain=None, name='foo', expire=84600, record_type='A',
                                               content='1.2.3.4')
        with self.assertRaises(TransipRestException):
            self.transip_client.post_dns_entry(domain=testdomain, name=None, expire=84600, record_type='A',
                                               content='1.2.3.4')
        with self.assertRaises(TransipRestException):
            self.transip_client.post_dns_entry(domain=testdomain, name='foo', expire=84600, record_type=None,
                                               content='1.2.3.4')
        with self.assertRaises(TransipRestException):
            self.transip_client.post_dns_entry(domain=testdomain, name='foo', expire=84600, record_type='A',
                                               content=None)
        with self.assertRaises(TransipRestException):
            self.transip_client.post_dns_entry(domain=testdomain, name='foo', expire=84600, record_type='B',
                                               content='1.2.3.4')

        with self.assertRaises(TransipRestException):
            self.transip_client.delete_dns_entry(domain=None, name='foo', expire=84600, record_type='A',
                                                 content='1.2.3.4')
        with self.assertRaises(TransipRestException):
            self.transip_client.delete_dns_entry(domain=testdomain, name=None, expire=84600, record_type='A',
                                                 content='1.2.3.4')
        with self.assertRaises(TransipRestException):
            self.transip_client.delete_dns_entry(domain=testdomain, name='foo', expire=84600, record_type=None,
                                                 content='1.2.3.4')
        with self.assertRaises(TransipRestException):
            self.transip_client.delete_dns_entry(domain=testdomain, name='foo', expire=84600, record_type='A',
                                                 content=None)
        with self.assertRaises(TransipRestException):
            self.transip_client.delete_dns_entry(domain=testdomain, name='foo', expire=84600, record_type='B',
                                                 content='1.2.3.4')

        with self.assertRaises(TransipRestException):
            self.transip_client.patch_dns_entry(domain=None, name='foo', expire=84600, record_type='A',
                                                content='1.2.3.4')
        with self.assertRaises(TransipRestException):
            self.transip_client.patch_dns_entry(domain=testdomain, name=None, expire=84600, record_type='A',
                                                content='1.2.3.4')
        with self.assertRaises(TransipRestException):
            self.transip_client.patch_dns_entry(domain=testdomain, name='foo', expire=84600, record_type=None,
                                                content='1.2.3.4')
        with self.assertRaises(TransipRestException):
            self.transip_client.patch_dns_entry(domain=testdomain, name='foo', expire=84600, record_type='A',
                                                content=None)
        with self.assertRaises(TransipRestException):
            self.transip_client.patch_dns_entry(domain=testdomain, name='foo', expire=84600, record_type='B',
                                                content='1.2.3.4')

    # the /domains/{domainName}/dnssec endpoint seems to be broken at TransIP
    # 20200122 TODO: fix this when it is working at TransIP side
    @expectedFailure
    def test_get_dnssec(self):
        dnssec_entries = self.transip_client.get_dnssec('')
        self.assertEqual(len(dnssec_entries), 0)
        dnssec_entries = self.transip_client.get_dnssec(None)
        self.assertEqual(len(dnssec_entries), 0)

        # I would expect a 404 here, but TransIP returns a 500...
        # ticket has been sent to TransIP Support
        with self.assertRaises(UnknownResultException):
            self.transip_client.get_dnssec(testdomain + '.invalidtld')
        dnssec_entries = self.transip_client.get_dnssec(testdomain)
        self.assertGreater(len(dnssec_entries), 0)

    def test_invalidkey(self):
        wrongkey = RSAkey[:50] + random_string() + RSAkey[60:]
        with self.assertRaises(TransipTokenAuthorisationException):
            TransipRestClient(user=transipaccount, rsaprivate_key=wrongkey)

    def test_get_nameservers(self):
        nameservers = self.transip_client.get_nameservers(testdomain)
        self.assertIsInstance(nameservers, list, msg="expected list when calling get_nameservers")
        self.assertGreater(len(nameservers), 0)
        for nameserver in nameservers:
            for key in ['hostname', 'ipv4', 'ipv6']:
                self.assertTrue(key in nameserver, msg=f'Expected key {key} in nameserver dictionary')
        with self.assertRaises(TransIPRestDomainNotFound,
                               msg="Expected to raise TransIPRestDomainNotFound when requesting nameservers " +
                                   "for example.com"):
            self.transip_client.get_nameservers('example.com')

        nameservers = self.transip_client.get_nameservers('')
        self.assertEqual(len(nameservers), 0)

        nameservers = self.transip_client.get_nameservers(None)
        self.assertEqual(len(nameservers), 0)

        with self.assertRaises(TransIPRestDomainNotFound):
            self.transip_client.get_nameservers(testdomain + '.invalidtld')

    def test_get_domain_actions(self):
        actions = self.transip_client.get_domain_actions(testdomain)
        self.assertIsInstance(actions, dict)
        for key in ['name', 'message', 'hasFailed']:
            self.assertTrue((key in actions), msg=f'Expected key {key} in actions')

        actions = self.transip_client.get_domain_actions('')
        self.assertEqual(len(actions), 0)

        actions = self.transip_client.get_domain_actions(None)
        self.assertEqual(len(actions), 0)

        with self.assertRaises(TransIPRestDomainNotFound):
            self.transip_client.get_domain_actions(testdomain + '.invalidtld')

    def test_get_zone_file(self):
        zonefile = self.transip_client.get_domain_zone_file(testdomain)
        self.assertIsInstance(zonefile, str)
        self.assertGreater(len(zonefile), 0)

        zonefile = self.transip_client.get_domain_zone_file('')
        self.assertEqual(len(zonefile), 0)

        zonefile = self.transip_client.get_domain_zone_file(None)
        self.assertEqual(len(zonefile), 0)

        with self.assertRaises(TransIPRestDomainNotFound):
            self.transip_client.get_domain_zone_file(testdomain + '.invalidtld')
