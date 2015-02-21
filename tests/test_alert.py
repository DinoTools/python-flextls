import binascii

from flextls.protocol.alert import Alert
from flextls.protocol.record import SSLv3Record


class TestSSLv3Alert(object):
    alert_01 = b"15030000020102"

    def test_decode(self):
        (record, data) = SSLv3Record.decode(
            binascii.unhexlify(
                self.alert_01
            )
        )
        assert len(data) == 0

        assert isinstance(record, SSLv3Record)
        assert record.version.major == 3
        assert record.version.minor == 0
        assert record.length == 2

        alert = record.payload
        assert isinstance(alert, Alert)
        assert alert.level == 1
        assert alert.description == 2

    def test_encode(self):
        record = SSLv3Record()
        alert = Alert()
        alert.level = 1
        alert.description = 2
        record.set_payload(alert)

        data = record.encode()
        assert binascii.hexlify(data) == self.alert_01