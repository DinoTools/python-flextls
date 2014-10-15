"""
The SSL/TLS Handshake Protocol
"""

from flextls.field import UInteger3Field
from flextls.field import UByteEnumField
from flextls.field import VectorUByteField
from flextls.field import VersionField, RandomField, CipherSuitesField, CompressionMethodsField, ExtensionsField, CipherSuiteField, CompressionMethodField
from flextls.protocol import Protocol


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

    def dissect(self, data):
        data = Protocol.dissect(self, data)
        return data


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

    def dissect(self, data):
        data = Protocol.dissect(self, data)
        return data

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

    def dissect(self, data):
        data = Protocol.dissect(self, data)
        return data

Handshake.add_payload_type(2, ServerHello)


class Certificate(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            # ToDo: add certificate field
        ]

    def dissect(self, data):
        data = Protocol.dissect(self, data)
        return data

Handshake.add_payload_type(11, Certificate)


class ServerKeyExchange(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            # ToDo: need a state object to parse the server params
        ]

    def dissect(self, data):
        data = Protocol.dissect(self, data)
        return data

Handshake.add_payload_type(12, Certificate)


class ServerHelloDone(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = []

    def dissect(self, data):
        data = Protocol.dissect(self, data)
        return data

Handshake.add_payload_type(14, ServerHelloDone)


class ClientKeyExchange(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = []

    def dissect(self, data):
        data = Protocol.dissect(self, data)
        return data

Handshake.add_payload_type(16, ClientKeyExchange)
