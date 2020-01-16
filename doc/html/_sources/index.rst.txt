
TransIP REST API Client
***********************

Documentation about the Python3 TransIP REST CLient

Release v\ |version|.

TransIP_ is a Dutch ISP offering various services like domain registration, DNS hosting, VPS services, storage. They
offer a REST API_ to be able to programatically order and configure these services. This API client is a Python
abstraction for this API. Obviously, this only works when you are a TransIP customer.

The module was built by Startmail.com in 2020.


.. _TransIP: https://www.transip.nl/
.. _API: https://api.transip.nl/rest/docs.html

TransipRestClient
=================

These are the classes that are important:

.. toctree::
    :maxdepth: 2

    transip_rest_client
    transip_token
    generic_rest_client
    transip_rest_client_exceptions

Synopsis
========

.. code-block:: python

    from transip_rest_client import TransipRestClient

    with open('rsaprivatekey.txt', 'r') as f:
        my_RSA_key = f.read()
    client = TransipRestClient(user='myaccountname', RSAprivate_key=my_RSA_key)
    client.post_dns_entry(domain='example.com', name='www', type='A', content='1.2.3.4')


Getting it working
==================

To work with the REST API, there are a few steps to take:

- have an account at TransIP
- turn API on (log in and enable it on the `api page`_)
- Generate a keypair on that same page; copy the Private Key that is shown once (save it in a file called privatekey.txt
- whitelist the IP address where the client is running
- convert the private key to an RSA private key (you need openssl tools installed)::

    openssl rsa -in privatekey.txt -out rsaprivatekey.txt


.. _api page: https://www.transip.nl/cp/account/api/

- this RSA private key is needed to be able to authenticate to the API

Status
======
As of jan 2020, the client is not (yet) completely implemented; DNS functions are working. But implementing the rest
should be fairly straightforward by looking at the different functions in ``transip_rest_client.py``

Why do all the tests fail?
==========================
TransIP does not offer a test API, nor a key with access to a test account. To make the tests working you will have to
add a file ``auth_setup.py`` in the ``tests`` directory that defines values for your TransIP account, your key, and an
existing domain in that account to edit like this example::

    transipaccount = 'myaccount'
    RSAkey = '-----BEGIN RSA PRIVATE KEY-----\n<myRSAKey>\n-----END RSA PRIVATE KEY-----'
    testdomain = 'mydomain.com'

the ``auth_setup.py`` is not part of the distribution for obvious reasons...

License
=======
This software is released under the :ref:`mit_license`.

.. toctree::
    :maxdepth: 2

    license

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
