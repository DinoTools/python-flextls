from flextls._registry import Registry
from flextls.__about__ import (
    __author__, __copyright__, __email__, __license__, __summary__, __title__,
    __uri__, __version__
)
from flextls.exception import NotEnoughData
from flextls.protocol.record import RecordSSLv3
from flextls.protocol.handshake import Handshake

registry = Registry()

class ConnectionState(object):
    def __init__(self):
        self.entity = None
        self.prf_algorithm = None
        self.bulk_cipher_algorithm = None
        self.cipher_type = None
        self.enc_key_length = None
        self.fixed_iv_length = None
        self.record_iv_length = None
        self.mac_algorithm = None
        self.mac_length = None
        self.mac_key_length = None
        self.compression_algorithm = None
        self.master_secret = None
        self.client_random = None
        self.server_random = None


class BaseConnection(object):
    def __init__(self):
        self._raw_stream_data = b""

        self._cur_record_type = None
        self._cur_record_data = b""
        # ToDo: name
        self._decoded_records = []

    def _decode_record_payload(self):
        while len(self._cur_record_data) > 0:
            try:
                (obj, data) = RecordSSLv3.decode_raw_payload(
                    self._cur_record_type,
                    self._cur_record_data,
                    payload_auto_decode=True
                )
                self._cur_record_data = data
                self._decoded_records.append(obj)

            except NotEnoughData:
                break

    def clear_records(self):
        self._decoded_records.clear()

    def decode(self, data):
        self._raw_stream_data += data
        while True:
            try:
                (obj, data) = RecordSSLv3.decode(
                    self._raw_stream_data,
                    payload_auto_decode=False
                )
                if self._cur_record_type is None:
                    self._cur_record_type = obj.content_Type

                if self._cur_record_type != obj.content_type:
                    self._decode_record_payload()
                    self._cur_record_data = b""
                    self._cur_record_type = obj.content_type

                self._cur_record_data += obj.payload

                self._raw_stream_data = data
                self._decode_record_payload()

            except NotEnoughData:
                break

    def is_empty(self):
        return len(self._decoded_records) == 0

    def pop_record(self):
        return self._decoded_records.pop(0)


class TLSv10Connection(BaseConnection):
    pass