"""
The SSL/TLS Handshake Protocol
"""

from flextls.field import UInteger3Field, UShortField, UByteField
from flextls.field import UByteEnumField
from flextls.field import VectorUByteField
from flextls.field import VersionField, RandomField, CipherSuitesField, CompressionMethodsField, ExtensionsField, CipherSuiteField, CompressionMethodField
from flextls.field import CertificateListField
from flextls.field import SSLv2CipherSuiteField
from flextls.protocol import Protocol


class DTLSv10Handshake(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UByteEnumField(
                "type",
                None,
                {
                    0: "hello_request",
                    1: "client_hello",
                    2: "server_hello",
                    3: "hello_verify_request",
                    11: "certificate",
                    12: "server_key_exchange",
                    13: "certificate_request",
                    14: "server_hello_done",
                    15: "certificate_verify",
                    16: "client_key_exchange",
                    20: "finished",
                    255: None
                }
            ),
            UInteger3Field("length", 0),
            UShortField("message_seq", 0),
            UInteger3Field("fragment_offset", 0),
            UInteger3Field("fragment_length", 0)
        ]
        self.payload_identifier_field = "type"
        self.payload_length_field = "length"


class DTLSv10ClientHello(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            RandomField("random"),
            VectorUByteField("session_id"),
            VectorUByteField("cookie"),
            CipherSuitesField("cipher_suites"),
            CompressionMethodsField("compression_methods"),
            ExtensionsField("extensions"),
        ]

DTLSv10Handshake.add_payload_type(1, DTLSv10ClientHello)


class DTLSv10HelloVerifyRequest(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            VectorUByteField("cookie")
        ]

DTLSv10Handshake.add_payload_type(3, DTLSv10HelloVerifyRequest)


class Handshake(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UByteEnumField(
                "type",
                None,
                {
                    0: "hello_request",
                    1: "client_hello",
                    2: "server_hello",
                    11: "certificate",
                    12: "server_key_exchange",
                    13: "certificate_request",
                    14: "server_hello_done",
                    15: "certificate_verify",
                    16: "client_key_exchange",
                    20: "finished",
                    255: None
                }
            ),
            UInteger3Field("length", 0),
        ]
        self.payload_identifier_field = "type"
        self.payload_length_field = "length"

class ClientHello(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            RandomField("random"),
            VectorUByteField("session_id"),
            CipherSuitesField("cipher_suites"),
            CompressionMethodsField("compression_methods"),
            ExtensionsField("extensions"),
        ]

Handshake.add_payload_type(1, ClientHello)


class ServerHello(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            RandomField("random"),
            VectorUByteField("session_id"),
            CipherSuiteField("cipher_suite"),
            CompressionMethodField("compression_method"),
            ExtensionsField("extensions"),
        ]

DTLSv10Handshake.add_payload_type(2, ServerHello)
Handshake.add_payload_type(2, ServerHello)


class ServerCertificate(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            CertificateListField("certificate_list"),
        ]

DTLSv10Handshake.add_payload_type(11, ServerCertificate)
Handshake.add_payload_type(11, ServerCertificate)


class ServerKeyExchange(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            # ToDo: need a state object to parse the server params
        ]

DTLSv10Handshake.add_payload_type(12, ServerKeyExchange)
Handshake.add_payload_type(12, ServerKeyExchange)


class ServerHelloDone(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = []

DTLSv10Handshake.add_payload_type(14, ServerHelloDone)
Handshake.add_payload_type(14, ServerHelloDone)


class ClientKeyExchange(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = []

Handshake.add_payload_type(16, ClientKeyExchange)


class SSLv2ClientHello(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            UShortField("cipher_suites_length", 0),
            UShortField("session_id_length", 0),
            UShortField("challenge_length", 0),
        ]
        self.cipher_suites = []
        self.session_id = b""
        self.challenge = b""

    def assemble(self):
        cipher_data = b""
        for cipher in self.cipher_suites:
            cipher_data = cipher_data + cipher.assemble()

        if len(self.challenge) == 0:
            # ToDo: error
            pass

        self.cipher_suites_length = len(cipher_data)
        self.session_id_length = len(self.session_id)
        self.challenge_length = len(self.challenge)

        data = cipher_data
        data += self.session_id
        data += self.challenge

        data = Protocol.assemble(self) + data
        return data

    def dissect(self, data, payload_auto_decode=True):
        data = Protocol.dissect(
            self,
            data,
            payload_auto_decode=payload_auto_decode
        )
        cipher_data = data[:self.cipher_suites_length]
        data = data[self.cipher_suites_length:]
        while len(cipher_data) > 0:
            if len(cipher_data) < 3:
                # ToDo: error
                break
            cipher = SSLv2CipherSuiteField()
            cipher_data = cipher.dissect(cipher_data)
            self.cipher_suites.append(cipher)

        self.session_id = data[:self.session_id_length]
        data = data[self.session_id_length:]
        self.challenge = data[:self.challenge_length]
        data = data[self.challenge_length:]

        return data


class SSLv2ServerHello(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            UByteField("session_id_hit", 0),
            UByteField("certificate_type", 0),
            VersionField("version"),
            UShortField("certificate_length", 0),
            UShortField("cipher_suites_length", 0),
            UShortField("connection_id_length", 0),
        ]
        self.certificate = b""
        self.cipher_suites = []
        self.connection_id = b""

    def dissect(self, data, payload_auto_decode=True):
        data = Protocol.dissect(
            self,
            data,
            payload_auto_decode=payload_auto_decode
        )

        self.certificate = data[:self.certificate_length]
        data = data[self.certificate_length:]

        cipher_data = data[:self.cipher_suites_length]
        data = data[self.cipher_suites_length:]
        while len(cipher_data) > 0:
            if len(cipher_data) < 3:
                # ToDo: error
                break
            cipher = SSLv2CipherSuiteField()
            cipher_data = cipher.dissect(cipher_data)
            self.cipher_suites.append(cipher)

        self.connection_id = data[:self.connection_id_length]
        data = data[self.connection_id_length:]

        return data
