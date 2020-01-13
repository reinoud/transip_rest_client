TransIP Python 3 REST API client
================================

This module implements a Python 3 client for the REST API of TransIP.nl (A dutch service provider

Overview
--------

TransIP offers a REST API to query and modify services. TransIP hosts excellent `documentation`_ on which this code is built


.. _documentation: https://api.transip.nl/rest/docs.html

Getting it working
------------------

To work with the REST API, there are a few steps to take:

- have an account at TransIP
- turn API on (log in and enable it on the `api page`_)
- Generate a keypair on that same page; copy the Private Key that is shown once (save it in a file called privatekey.txt
- whitelist the IP address where the client is running
- convert the private key to an RSA private key (you need openssl tools installed)::

    openssl rsa -in privatekey.txt -out rsaprivatekey.txt


.. _api page: https://www.transip.nl/cp/account/api/

- this RSA private key is needed to be able to authenticate to the API

Usage
-----
With the file rsaprivatekey.txt in current directory::

    from transip_rest_client import TransipRestClient

    with open('rsaprivatekey.txt', 'r') as f:
        my_RSA_key = f.read()
    client = TransipRestClient(user='myaccountname', RSAprivate_key=my_RSA_key)
    client.post_dns_entry(domain='example.com', name='www', type='A', content='1.2.3.4')


getting tests working
---------------------
Since TransIP does not provide a test environment nor a key to test with, the unittests depend on your credentials and
are not supplied. The Unittests expect a file auth_setup.py to be present in the test directory with credentials. It
should look like this::

    transipaccount = 'myaccount'
    RSAkey = '-----BEGIN RSA PRIVATE KEY-----\n<myRSAKey>\n-----END RSA PRIVATE KEY-----'
    testdomain = 'mydomain.com'

The tests do not (yet) provide a stub for offline-testing

Status
------
As of january 2020, the client is not complete; only DNS features have been implemented. Other functionality can (and
will) be added to transip_rest_client.py