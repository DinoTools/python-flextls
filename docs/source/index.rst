Welcome to FlexTLS's documentation!
=====================================

Features
--------

* Supported cryptographic protocols:

  * SSLv2, SSLv3, TLS 1.0, TLS 1.1 and TLS 1.2
  * DTLS 1.0 and DTLS 1.2

* Decode and encode SSL/TLS/DTLS records
* Handle fragmentation

  * TLS - Handle fragmentation on the record layer
  * DTLS - Handle fragmented handshake messages

* Handle connection state

Installation
------------

You can install ``FlexTLS`` with ``pip``:

.. code-block:: console

    $ pip install flextls

See :doc:`Introduction <introduction>` for more information.

Contents:

.. toctree::
   :maxdepth: 2

   introduction
   changelog

API Documentation
-----------------

.. toctree::
   :maxdepth: 2

   api/connection
   api/exception
   api/field
   api/helper
   api/protocol

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

