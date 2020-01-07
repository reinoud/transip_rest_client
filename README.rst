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

    import transip_rest_client
    account = 'myaccount'
    with open('rsaprivatekey.txt', 'r') as f:
        key = f.read()
    client = transip_rest_client.TransipRestClient(user=account, RSAprivate_key=key)
    print(client.ping())

output::

    pong


getting tests working
---------------------
