import binascii

from flextls.protocol.record import Record
from flextls.protocol.handshake.extension import Extension, SessionTicketTLS, ServerNameIndication, ApplicationLayerProtocolNegotiation, NextProtocolNegotiation
from flextls.field import ServerNameField, HostNameField, VectorUInt8Field


class TestApplicationLayerProtocolNegotiation(object):
    @staticmethod
    def _get_data():
        # Type: Application Layer Protocol Negotiation, Length: 25
        data = b"00100019"
        # ALP Extensioin Length: 23
        data += b"0017"
        # Length: 6, Name: spdy/3
        data += b"06737064792f33"
        # Length: 6, Name: spdy/2
        data += b"06737064792f32"
        # Length: 8, Name: http/1.1
        data += b"08687474702f312e31"
        return data

    def test_encode(self):
        tmp = Extension() + ApplicationLayerProtocolNegotiation()
        a = VectorUInt8Field(None)
        a.value = b"spdy/3"
        tmp.payload.protocol_name_list.append(a)
        a = VectorUInt8Field(None)
        a.value = b"spdy/2"
        tmp.payload.protocol_name_list.append(a)
        a = VectorUInt8Field(None)
        a.value = b"http/1.1"
        tmp.payload.protocol_name_list.append(a)

        data = tmp.encode()
        data_should = self._get_data()
        assert binascii.hexlify(data) == data_should

    def test_decode(self):
        data = self._get_data()

        (obj, data) = Extension.decode(binascii.unhexlify(data))
        assert len(obj.payload.protocol_name_list) == 3
        assert obj.payload.protocol_name_list[0].value == b"spdy/3"
        assert obj.payload.protocol_name_list[1].value == b"spdy/2"
        assert obj.payload.protocol_name_list[2].value == b"http/1.1"


class TestNextProtocolNegotiation(object):
    @staticmethod
    def _get_data():
        # Type: Next Protocol Negotiation, Length: 40
        data = b"33740028"
        # Length: 2, Name: h2
        data += b"026832"
        # Length: 5, Name: h2-15
        data += b"0568322d3135"
        # Length: 5, Name: h2-14
        data += b"0568322d3134"
        # Length: 8, Name: spdy/3.1
        data += b"08737064792f332e31"
        # Length: 6, Name: spdy/3
        data += b"06737064792f33"
        # Length: 8, Name: http/1.1
        data += b"08687474702f312e31"
        return data

    def test_encode(self):
        tmp = Extension() + NextProtocolNegotiation()
        a = VectorUInt8Field(None)
        a.value = b"h2"
        tmp.payload.payload.append(a)
        a = VectorUInt8Field(None)
        a.value = b"h2-15"
        tmp.payload.payload.append(a)
        a = VectorUInt8Field(None)
        a.value = b"h2-14"
        tmp.payload.payload.append(a)
        a = VectorUInt8Field(None)
        a.value = b"spdy/3.1"
        tmp.payload.payload.append(a)
        a = VectorUInt8Field(None)
        a.value = b"spdy/3"
        tmp.payload.payload.append(a)
        a = VectorUInt8Field(None)
        a.value = b"http/1.1"
        tmp.payload.payload.append(a)

        data = tmp.encode()
        data_should = self._get_data()
        assert binascii.hexlify(data) == data_should

    def test_encode_empty(self):
        tmp = Extension() + NextProtocolNegotiation()
        data = tmp.encode()
        assert binascii.hexlify(data) == b"33740000"

    def test_decode(self):
        data = self._get_data()

        (obj, data) = Extension.decode(binascii.unhexlify(data))
        assert len(obj.payload.payload) == 6
        assert obj.payload.payload[0].value == b"h2"
        assert obj.payload.payload[1].value == b"h2-15"
        assert obj.payload.payload[2].value == b"h2-14"
        assert obj.payload.payload[3].value == b"spdy/3.1"
        assert obj.payload.payload[4].value == b"spdy/3"
        assert obj.payload.payload[5].value == b"http/1.1"

class TestSessionTicketTLS(object):

    def test_encode_empty(self):
        tmp = Extension() + SessionTicketTLS()
        data = tmp.encode()
        assert binascii.hexlify(data) == b"00230000"

    def test_decode_empty(self):
        data = b"00230000"
        (obj, data) = Extension.decode(binascii.unhexlify(data))
        print(obj.payload)
        assert len(obj.payload.data) == 0


class TestServerNameIndication(object):

    def test_encode(self):
        # Type: server_name, Length: 16
        data = b"00000010"
        # Length: 14
        data += b"000e"
        # Type: host_name, Length: 11, Name: example.org
        data += b"00000b6578616d706c652e6f7267"

        server_name = ServerNameField()
        server_name.payload = HostNameField("")
        server_name.payload.value = b"example.org"
        tmp_sni = ServerNameIndication()
        tmp_sni.server_name_list.append(server_name)
        tmp = Extension() + tmp_sni
        assert binascii.hexlify(tmp.encode()) == data

    def test_decode_empty(self):
        # Type: server_name, Length: 0
        data = b"00000000"
        (obj, data) = Extension.decode(binascii.unhexlify(data))
        assert isinstance(obj, Extension)
        assert isinstance(obj.payload, ServerNameIndication)
        assert len(obj.payload.server_name_list) == 0

    def test_decode_name(self):
        # Type: server_name, Length: 16
        data = b"00000010"
        # Length: 14
        data += b"000e"
        # Type: host_name, Length: 11, Name: example.org
        data += b"00000b6578616d706c652e6f7267"

        (obj, data) = Extension.decode(binascii.unhexlify(data))
        assert isinstance(obj, Extension)
        assert isinstance(obj.payload, ServerNameIndication)
        assert len(obj.payload.server_name_list) == 1
        assert obj.payload.server_name_list[0].payload.value == b"example.org"
