"""
The SSL/TLS Record Protocol
"""
import struct


from flextls.field import UByteEnumField, UShortField, VersionField
from flextls.protocol import Protocol
from flextls.protocol.alert import Alert
from flextls.protocol.change_cipher_spec import ChangeCipherSpec
from flextls.protocol.handshake import Handshake, SSLv2ClientHello, SSLv2ServerHello
from flextls.protocol.heartbeat import Heartbeat


class Record(Protocol):
    @classmethod
    def decode(cls, data, connection_state=None):
        if data[3] == 0x00 and data[4] == 0x02:
            obj = RecordSSLv2(
                connection_state=connection_state
            )
        elif data[1] == 0x03:
            obj = RecordSSLv3(
                connection_state=connection_state
            )

        data = obj.dissect(data)
        return (obj, data)


class RecordSSLv2(Protocol):

    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.length = 0
        self.is_escape = None
        self.padding_length = None
        self.padding = b""
        self.type = None

    def dissect(self, data):
        # Is it 2 or 3 bytes header
        if struct.unpack("!B", data[:1])[0] & 0x80 == 0:
            tmp = struct.unpack("!BBB", data[:3])
            data = data[3:]
            self.length = ((tmp[0] & 0x3f) << 8) | tmp[1]
            self.is_escape = ((tmp[0] & 0x40) != 0)
            self.padding_length = tmp[2]
        else:
            tmp = struct.unpack("!BB", data[:2])
            data = data[2:]
            self.length = ((tmp[0] & 0x7f) << 8) | tmp[1]

        self.type = struct.unpack("!B", data[:1])[0]
        data = data[1:]

        payload_class = self.payload_list.get(
            self.type,
            None
        )

        if payload_class is None:
            self.payload = data
        else:
            (obj, data) = payload_class.decode(
                data,
                connection_state=self._connection_state
            )
            self.payload = obj

        return data


class RecordSSLv3(Protocol):

    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UByteEnumField(
                "content_type",
                None,
                {
                    20: "change_cipher_spec",
                    21: "alert",
                    22: "handshake",
                    23: "application_data",
                    255: None
                }
            ),
            VersionField("version"),
            UShortField("length", 0),
        ]
        self.payload_identifier_field = "content_type"
        self.payload_length_field = "length"

    def dissect(self, data):
        data = Protocol.dissect(self, data)

        return data


RecordSSLv2.add_payload_type(1, SSLv2ClientHello)
RecordSSLv2.add_payload_type(4, SSLv2ServerHello)
RecordSSLv3.add_payload_type(20, ChangeCipherSpec)
RecordSSLv3.add_payload_type(21, Alert)
RecordSSLv3.add_payload_type(22, Handshake)
RecordSSLv3.add_payload_type(24, Heartbeat)
