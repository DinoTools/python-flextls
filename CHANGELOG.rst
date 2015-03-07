Changelog
=========

0.3 - 2015-03-07
~~~~~~~~~~~~~~~~

* Add support for DTLS 1.0 and DTLS 1.2
* Add support to handle fragmentation on the record layer (TLS)
* Add support to handle fragmented handshake messages (DTLS)
* Add support to handle connection state
* Add support to decode ServerKeyExchange messages
* Change class names for consistent names
* Add additional tests
* Remove deprecated and unused code


0.2 - 2014-11-17
~~~~~~~~~~~~~~~~

* Add Registry to store global information

  * Add SSL and TLS cipher suites
  * Add named curves
  * Add signature and hash algorithms

* Add support to parse SSLv2 ClientHello and ServerHello packages
* Fixes (Thanks to Till Maas)


0.1 - 2014-10-15
~~~~~~~~~~~~~~~~

Proof of concept

* Initial release.

.. _`master`: https://github.com/DinoTools/python-flextls
