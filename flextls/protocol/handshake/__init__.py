"""
The SSL/TLS Handshake Protocol
"""

from flextls.field import UInt24Field, UInt16Field, UInt8Field
from flextls.field import UInt8EnumField
from flextls.field import VectorUInt8Field
from flextls.field import VersionField, RandomField, CipherSuitesField, CompressionMethodsField, ExtensionsField, CipherSuiteField, CompressionMethodField
from flextls.field import CertificateListField
from flextls.field import SSLv2CipherSuiteField
from flextls.protocol import Protocol


class DTLSv10Handshake(Protocol):
    """
    Handle DTLS 1.0 and 1.2 Handshake protocol
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UInt8EnumField(
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
            UInt24Field("length", 0),
            UInt16Field("message_seq", 0),
            UInt24Field("fragment_offset", 0),
            UInt24Field("fragment_length", 0)
        ]
        self.payload_identifier_field = "type"
        self.payload_length_field = "length"
        self.payload_fragment_length_field = "fragment_length"
        self.payload_fragment_offset_field = "fragment_offset"

    def assemble(self):
        Protocol.assemble(self)
        # ToDo: Fragmentation is not supported
        self.fragment_offset = 0
        self.fragment_length = self.length
        return Protocol.assemble(self)

    def concat(self, *parts):
        found = True
        while found:
            found = False
            tmp_parts = []
            for part in parts:
                fragment_length = self.get_field_value(self.payload_fragment_length_field)
                fragment_offset = self.get_field_value(self.payload_fragment_offset_field)
                part_fragment_length = part.get_field_value(part.payload_fragment_length_field)
                part_fragment_offset = part.get_field_value(part.payload_fragment_offset_field)
                fragment_end = fragment_offset + fragment_length
                part_fragment_end = part_fragment_offset + part_fragment_length

                if part_fragment_end < fragment_offset:
                    tmp_parts.append(part)
                    continue

                if part_fragment_offset > fragment_end:
                    tmp_parts.append(part)
                    continue

                if part_fragment_offset < fragment_offset and part_fragment_end >= fragment_offset:
                    part_length = part_fragment_offset - fragment_offset
                    self.payload += part.payload[:part_length]
                    self.set_field_value(self.payload_fragment_offset_field, part_fragment_offset)
                    self.set_field_value(self.payload_fragment_length_field, len(self.payload))

                if part_fragment_offset <= fragment_end and part_fragment_end > fragment_end:
                    part_offset = fragment_end - part_fragment_offset
                    self.payload += part.payload[part_offset:]
                    self.set_field_value(self.payload_fragment_length_field, len(self.payload))

                found = True

            parts = tmp_parts

        return parts


class DTLSv10ClientHello(Protocol):
    """
    Handle DTLS 1.0 and 1.2 Client Hello messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            RandomField("random"),
            VectorUInt8Field("session_id"),
            VectorUInt8Field("cookie"),
            CipherSuitesField("cipher_suites"),
            CompressionMethodsField("compression_methods"),
            ExtensionsField("extensions"),
        ]

DTLSv10Handshake.add_payload_type(1, DTLSv10ClientHello)


class DTLSv10HelloVerifyRequest(Protocol):
    """
    Handle DTLS 1.0 and 1.2 Hello Verify Request messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            VectorUInt8Field("cookie")
        ]

DTLSv10Handshake.add_payload_type(3, DTLSv10HelloVerifyRequest)


class Handshake(Protocol):
    """
    Handle SSLv3 and TLS 1.0, 1.1 and 1.2 Handshake protocol
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UInt8EnumField(
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
            UInt24Field("length", 0),
        ]
        self.payload_identifier_field = "type"
        self.payload_length_field = "length"


class ClientHello(Protocol):
    """
    Handle SSLv3 and TLS 1.0, 1.1 and 1.2 Client Hello messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            RandomField("random"),
            VectorUInt8Field("session_id"),
            CipherSuitesField("cipher_suites"),
            CompressionMethodsField("compression_methods"),
            ExtensionsField("extensions"),
        ]

Handshake.add_payload_type(1, ClientHello)


class ServerHello(Protocol):
    """
    Handle SSLv3 and TLS 1.0, 1.1 and 1.2 Server Hello messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            RandomField("random"),
            VectorUInt8Field("session_id"),
            CipherSuiteField("cipher_suite"),
            CompressionMethodField("compression_method"),
            ExtensionsField("extensions"),
        ]

DTLSv10Handshake.add_payload_type(2, ServerHello)
Handshake.add_payload_type(2, ServerHello)


class ServerCertificate(Protocol):
    """
    Handle SSLv3 and TLS 1.0, 1.1 and 1.2 and DLTS 1.0 and 1.2 Server Certificate messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            CertificateListField("certificate_list"),
        ]

DTLSv10Handshake.add_payload_type(11, ServerCertificate)
Handshake.add_payload_type(11, ServerCertificate)


class ServerKeyExchange(Protocol):
    """
    Handle SSLv3 and TLS 1.0, 1.1 and 1.2 and DLTS 1.0 and 1.2 Server Key Exchange messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            # ToDo: need a state object to parse the server params
        ]

DTLSv10Handshake.add_payload_type(12, ServerKeyExchange)
Handshake.add_payload_type(12, ServerKeyExchange)


class ServerHelloDone(Protocol):
    """
    Handle SSLv3 and TLS 1.0, 1.1 and 1.2 and DLTS 1.0 and 1.2 Server Hello Done messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = []

DTLSv10Handshake.add_payload_type(14, ServerHelloDone)
Handshake.add_payload_type(14, ServerHelloDone)


class ClientKeyExchange(Protocol):
    """
    Handle SSLv3 and TLS 1.0, 1.1 and 1.2 and DLTS 1.0 and 1.2 Client Key Exchange messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = []

DTLSv10Handshake.add_payload_type(16, ClientKeyExchange)
Handshake.add_payload_type(16, ClientKeyExchange)


class SSLv2ClientHello(Protocol):
    """
    Handle SSLv2 Client Hello messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            VersionField("version"),
            UInt16Field("cipher_suites_length", 0),
            UInt16Field("session_id_length", 0),
            UInt16Field("challenge_length", 0),
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
    """
    Handle SSLv2 Server Hello messages
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.payload = None
        self.fields = [
            UInt8Field("session_id_hit", 0),
            UInt8Field("certificate_type", 0),
            VersionField("version"),
            UInt16Field("certificate_length", 0),
            UInt16Field("cipher_suites_length", 0),
            UInt16Field("connection_id_length", 0),
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
