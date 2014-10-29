import binascii

from flextls.protocol.record import Record
from flextls.protocol.handshake.extension import Extension, SessionTicketTLS, ServerNameIndication
from flextls.field import ServerNameField, HostNameField


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
