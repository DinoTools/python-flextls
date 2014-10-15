"""
The SSL/TLS Record Protocol
"""

from flextls.field import UByteEnumField, UShortField, VersionField
from flextls.protocol import Protocol
from flextls.protocol.alert import Alert
from flextls.protocol.change_cipher_spec import ChangeCipherSpec
from flextls.protocol.handshake import Handshake
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
        self.fields = [
            UShortField("length", 0),
            UByteEnumField(
                "type",
                None,
                {
                    1: "client_hello",
                    255: None
                }
            ),
            VersionField("version"),
        ]

    def dissect(self, data):
        data = Protocol.dissect(self, data)

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


RecordSSLv3.add_payload_type(20, ChangeCipherSpec)
RecordSSLv3.add_payload_type(21, Alert)
RecordSSLv3.add_payload_type(22, Handshake)
RecordSSLv3.add_payload_type(24, Heartbeat)
