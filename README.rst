FlexTLS
=======

FlexTLS is an open source SSL and TLS python library.
It is designed to be used in SSL/TLS scanners and similar applications.
It must not be used as standalone crypto library.

You can find more information in the `documentation`_.

.. image:: https://pypip.in/version/flextls/badge.svg
    :target: https://pypi.python.org/pypi/flextls/
    :alt: Latest Version

.. image:: https://pypip.in/license/flextls/badge.svg
    :target: https://pypi.python.org/pypi/flextls/
    :alt: License

.. image:: https://travis-ci.org/DinoTools/python-flextls.svg?branch=master
    :target: https://travis-ci.org/DinoTools/python-flextls

.. image:: https://readthedocs.org/projects/python-flextls/badge/?version=latest
    :target: https://readthedocs.org/projects/python-flextls/?badge=latest
    :alt: Documentation Status

Features
--------

* Supported cryptographic protocols:

  * SSLv2, SSLv3, TLS 1.0, TLS 1.1 and TLS 1.2
  * DTLS 1.0

* Decode and encode SSL/TLS/DTLS records
* Handle fragmentation

  * TLS - Handle fragmentation on the record layer
  * DTLS - Handle fragmented handshake messages


Install
-------

**Requirements:**

* Python 2.6/2.7 or Python >= 3.2
* Python packages:

  * six >= 1.4.1


**Install:**

.. code-block:: console

    $ pip install flextls


License
-------

Published under the LGPLv3+ (see LICENSE for more information)

.. _`documentation`: http://python-flextls.readthedocs.org/
