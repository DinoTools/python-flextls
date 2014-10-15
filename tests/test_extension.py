import binascii

from flextls.protocol.record import Record
from flextls.protocol.handshake.extension import Extension, SessionTicketTLS


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
