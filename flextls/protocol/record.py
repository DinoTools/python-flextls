"""
The SSL/TLS Record Protocol
"""
import struct

import six

from flextls.exception import NotEnoughData
from flextls.field import UByteEnumField, UShortField, UInt48Field, VersionField
from flextls.protocol import Protocol
from flextls.protocol.alert import Alert
from flextls.protocol.change_cipher_spec import ChangeCipherSpec
from flextls.protocol.handshake import Handshake, DTLSv10Handshake
from flextls.protocol.handshake import SSLv2ClientHello, SSLv2ServerHello
from flextls.protocol.heartbeat import Heartbeat


class Record(Protocol):
    @classmethod
    def decode(cls, data, connection_state=None, payload_auto_decode=True):
        if len(data) < 4:
            raise NotEnoughData("Not enough data to decode header")

        if six.indexbytes(data, 3) == 0x00 and six.indexbytes(data, 4) == 0x02:
            obj = RecordSSLv2(
                connection_state=connection_state
            )
        elif six.indexbytes(data, 1) == 0x03:
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

    def assemble(self):
        data = b""
        payload = b""

        if isinstance(self.payload, Protocol):
            payload = self.payload.encode()
            for pay_pattern, pay_class in self.payload_list.items():
                if isinstance(self.payload, pay_class):
                    self.type = pay_pattern
                    break
        elif self.payload is not None:
            payload = self.payload

        data = struct.pack("!B", (self.type))
        data += payload
        data += self.padding

        self.length = len(data)

        # Is it 2 or 3 bytes header
        if len(self.padding) > 0:
            tmp = [0, 0, 0]
            tmp[0] = (self.length >> 8) & 0x3f
            tmp[1] = self.length & 0xff
            tmp[2] = len(self.padding)
            if self.is_escape == True:
                tmp[0] = tmp[0] | 0x40
            data = struct.pack("!BBB", *tmp) + data
        else:
            tmp = [0, 0]
            tmp[0] = (self.length >> 8) & 0x7f
            tmp[1] = self.length & 0xff
            tmp[0] = tmp[0] | 0x80
            data = struct.pack("!BB", *tmp) + data

        return data

    def dissect(self, data, payload_auto_decode=True):
        if len(data) < 2:
            raise NotEnoughData("Not enough data to decode header")

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

        if len(data) == 0:
            raise NotEnoughData("Not enough data to decode header")

        self.type = struct.unpack("!B", data[:1])[0]
        data = data[1:]

        payload_class = self.payload_list.get(
            self.type,
            None
         )

        if payload_class is None or payload_auto_decode is False:
            self.payload = data
        else:
            (obj, data) = payload_class.decode(
                data,
                connection_state=self._connection_state,
                payload_auto_decode=payload_auto_decode
            )
            self.payload = obj

        return data


class RecordDTLSv1(Protocol):

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
            UShortField("epoch", 0),
            UInt48Field("sequence_number", 0),
            UShortField("length", 0),
        ]
        self.payload_identifier_field = "content_type"
        self.payload_length_field = "length"


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


RecordDTLSv1.add_payload_type(22, DTLSv10Handshake)
RecordSSLv2.add_payload_type(1, SSLv2ClientHello)
RecordSSLv2.add_payload_type(4, SSLv2ServerHello)
RecordSSLv3.add_payload_type(20, ChangeCipherSpec)
RecordSSLv3.add_payload_type(21, Alert)
RecordSSLv3.add_payload_type(22, Handshake)
RecordSSLv3.add_payload_type(24, Heartbeat)
