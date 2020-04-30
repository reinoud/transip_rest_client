# Copyright (c) Dick Marinus, 2020
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

transipaccount = "transipdemo"
testdomain = "transipdemonstratie.com"

from transip_rest_client.tests.utils_for_test import random_string
from transip_rest_client import (
    TransipRestClient,
    TransipTokenAuthorisationException,
    TransIPRestDomainNotFound,
    TransIPRestRecordNotFound,
    TransipTokenGeneralException,
    TransipRestException,
)
from transip_rest_client.generic_rest_client import UnknownResultException


class TestTransipRestClientDemoAccount(TestCase):
    def setUp(self) -> None:
        self.transip_client = TransipRestClient(
            user="transipdemo",
            rsaprivate_key="",
            token="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6ImN3MiFSbDU2eDNoUnkjelM4YmdOIn0.eyJpc3MiOiJhcGkudHJhbnNpcC5ubCIsImF1ZCI6ImFwaS50cmFuc2lwLm5sIiwianRpIjoiY3cyIVJsNTZ4M2hSeSN6UzhiZ04iLCJpYXQiOjE1ODIyMDE1NTAsIm5iZiI6MTU4MjIwMTU1MCwiZXhwIjoyMTE4NzQ1NTUwLCJjaWQiOiI2MDQ0OSIsInJvIjpmYWxzZSwiZ2siOmZhbHNlLCJrdiI6dHJ1ZX0.fYBWV4O5WPXxGuWG-vcrFWqmRHBm9yp0PHiYh_oAWxWxCaZX2Rf6WJfc13AxEeZ67-lY0TA2kSaOCp0PggBb_MGj73t4cH8gdwDJzANVxkiPL1Saqiw2NgZ3IHASJnisUWNnZp8HnrhLLe5ficvb1D9WOUOItmFC2ZgfGObNhlL2y-AMNLT4X7oNgrNTGm-mespo0jD_qH9dK5_evSzS3K8o03gu6p19jxfsnIh8TIVRvNdluYC2wo4qDl5EW5BEZ8OSuJ121ncOT1oRpzXB0cVZ9e5_UVAEr9X3f26_Eomg52-PjrgcRJ_jPIUYbrlo06KjjX2h0fzMr21ZE023Gw",
        )

    def test_ping(self):
        answer = self.transip_client.ping()
        self.assertEqual(answer, "pong")

    def test_get_products(self):
        products = self.transip_client.get_products()
        self.assertIsInstance(
            products, dict, msg="expected a dict when calling get_products"
        )
        self.assertGreater(
            len(products),
            1,
            msg="expected more than 1 product when calling get_products",
        )

    def test_get_domains(self):
        domains = self.transip_client.get_domains()
        self.assertIsInstance(
            domains, list, msg="expected a list when calling get_domains"
        )
        self.assertGreater(
            len(domains),
            1,
            msg="expected more than 1 domain when calling get_domains",
        )

    def test_get_domain(self):
        domain = self.transip_client.get_domain("transipdemonstratie.com")
        self.assertIsInstance(
            domain, dict, msg="expected a dict when calling get_domain"
        )
        self.assertGreater(
            len(domain),
            1,
            msg="expected more than 1 domain when calling get_domain",
        )

    def test_get_domain_none(self):
        domain = self.transip_client.get_domain(None)
        self.assertEqual(domain, {})

    def test_get_domain_nonexisting(self):
        with self.assertRaises(TransIPRestDomainNotFound):
            self.transip_client.get_domain('example.com')

    def test_get_dns_entries(self):
        dns_entries = self.transip_client.get_dns_entries("transipdemonstratie.com")

        self.assertIsInstance(dns_entries, list,
                              msg="exepected a list when calling get_dns_entries")
        if len(dns_entries) > 0:
            from transip_rest_client.transip_rest_client import ALLOWED_TYPES
            allowed_types_string = ', '.join([f'"{x}"' for x in ALLOWED_TYPES])
            self.assertIn(dns_entries[0]['type'], ALLOWED_TYPES,
                          msg=f"expected {dns_entries[0]['type']} to be of allowed type ({allowed_types_string})")

    def test_get_dns_entries_none(self):
        domain = self.transip_client.get_dns_entries(None)
        self.assertEqual(domain, [])

    def test_get_dns_entries_nonexisting(self):
        with self.assertRaises(TransIPRestDomainNotFound):
            self.transip_client.get_dns_entries('example.com')

    def test_post_dns_entry(self):
        self.transip_client.post_dns_entry(domain='transipdemonstratie.com', name='test', expire=84600, record_type='A', content='1.2.3.4')

    def test_post_dns_entry_insufficient_arguments(self):
        with self.assertRaises(TransipRestException):
            self.transip_client.post_dns_entry()

    def test_post_dns_entry_invalid_record_type(self):
        with self.assertRaises(TransipRestException):
            self.transip_client.post_dns_entry(domain='transipdemonstratie.com', expire=84600, name='test', record_type='PTR', content='1.2.3.4')

    def test_patch_dns_entry(self):
        self.transip_client.patch_dns_entry(domain='transipdemonstratie.com', name='@', record_type='A', content='1.2.3.4')

    def test_patch_dns_entry_insufficient_arguments(self):
        with self.assertRaises(TransipRestException):
            self.transip_client.patch_dns_entry()

    def test_patch_dns_entry_invalid_record_type(self):
        with self.assertRaises(TransipRestException):
            self.transip_client.patch_dns_entry(domain='transipdemonstratie.com', expire=84600, name='test', record_type='PTR', content='1.2.3.4')

    def test_patch_dns_entry_record_not_found(self):
        with self.assertRaises(TransipRestException):
            self.transip_client.patch_dns_entry(domain='transipdemonstratie.com', expire=84600, name='test', record_type='A', content='1.2.3.4')

    def test_delete_dns_entry(self):
        self.transip_client.delete_dns_entry(domain='transipdemonstratie.com', name='@', record_type='A', expire=86400, content='37.97.254.27')

    def test_delete_dns_entry_insufficient_arguments(self):
        with self.assertRaises(TransipRestException):
            self.transip_client.delete_dns_entry()

    def test_delete_dns_entry_invalid_record_type(self):
        with self.assertRaises(TransipRestException):
            self.transip_client.delete_dns_entry(domain='transipdemonstratie.com', expire=84600, name='test', record_type='PTR', content='37.97.254.27')

    def test_delete_dns_entry_record_not_found(self):
        with self.assertRaises(TransipRestException):
            self.transip_client.delete_dns_entry(domain='transipdemonstratie.com', expire=84600, name='test', record_type='A', content='37.97.254.27')

    def test_get_dnssec(self):
        self.transip_client.get_dnssec('transipdemonstratie.com')

    def test_get_dnssec_none(self):
        domain = self.transip_client.get_dnssec(None)
        self.assertEqual(domain, {})

    #FIXME: doesn't work
    #def test_get_dnssec_domain_not_found(self):
    #    with self.assertRaises(TransIPRestDomainNotFound):
    #        self.transip_client.get_dnssec('example.com')

    def test_get_nameservers(self):
        self.transip_client.get_nameservers('transipdemonstratie.com')

    def test_get_nameservers_none(self):
        domain = self.transip_client.get_nameservers(None)
        self.assertEqual(domain, [])

    def test_get_nameservers_domain_not_found(self):
        with self.assertRaises(TransIPRestDomainNotFound):
            self.transip_client.get_nameservers('example.com')

    def test_get_domain_actions(self):
        self.transip_client.get_domain_actions('transipdemonstratie.com')

    def test_get_domain_actions_none(self):
        domain = self.transip_client.get_domain_actions(None)
        self.assertEqual(domain, {})

    def test_get_domain_actions_domain_not_found(self):
        with self.assertRaises(TransIPRestDomainNotFound):
            self.transip_client.get_domain_actions('example.com')

    #FIXME: doesn't work
    #def test_get_domain_zone_file(self):
    #    self.transip_client.get_domain_zone_file('transipdemonstratie.com')

    def test_get_domain_zone_file_none(self):
        domain = self.transip_client.get_domain_zone_file(None)
        self.assertEqual(domain, '')
