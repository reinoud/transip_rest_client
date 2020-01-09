
TransIP REST API Client
***********************

Documentation about the Python3 TransIP REST CLient

Release v\ |version|.


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
    account = 'myaccount'
    with open('rsaprivatekey.txt', 'r') as f:
        key = f.read()
    client = TransipRestClient(user=account, RSAprivate_key=key)
    print(client.ping())


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
