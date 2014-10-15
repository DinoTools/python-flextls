import binascii

from flextls.protocol.heartbeat import Heartbeat
from flextls.protocol.record import Record, RecordSSLv3


class TestHeartbeatResponse(object):
    def _get_record(self):
        # Heartbeat, TLS 1.1, Length 35
        data = b"1803020023"
        # Type: Response, Length 16
        data += b"020010"
        # payload
        data += b"d8030253435b909d9b720bbc0cbc2b92"
        # padding
        data += b"8f6617584abce2274a2c702898251f8f"

        (record, data) = Record().decode(binascii.unhexlify(data))
        return record

    def test_heartbeat_type(self):
        record = self._get_record()
        assert record.payload.type == 2

    def test_heartbeat_payload(self):
        record = self._get_record()
        assert len(record.payload.payload) == 16

    def test_heartbeat_padding(self):
        record = self._get_record()
        assert len(record.payload.padding) == 16


class TestHeartbeatCreate(object):
    def test_heartbeat_type(self):
        record = RecordSSLv3()
        hb = Heartbeat()
        hb.type = 1
        hb.payload = b"Heartbeat"
        hb.padding = b"1234567890123456"

        obj = record + hb
        # Heartbeat, SSL 3.0, Length 28
        data = b"180300001c"
        # Type: Request, Length 9
        data += b"010009"
        # Payload
        data += b"486561727462656174"
        # Padding
        data += b"31323334353637383930313233343536"
        assert binascii.unhexlify(data) == obj.encode()
