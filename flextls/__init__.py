from flextls._registry import Registry
from flextls.__about__ import (
    __author__, __copyright__, __email__, __license__, __summary__, __title__,
    __uri__, __version__
)


registry = Registry()

from flextls.protocol import Protocol
from flextls.protocol.record import RecordDTLSv10
from flextls.protocol.handshake import DTLSv10Handshake
from flextls.exception import NotEnoughData


class BaseDTLSConnection(object):
    def __init__(self):
        self._window = []
        self._window_next_seq = 0

        for i in range(0, 64):
            self._window.append(None)

        self._handshake_next_receive_seq = 0
        self._handshake_msg_queue = []

        self._decoded_records = []

    def _process(self, obj):
        if isinstance(obj, DTLSv10Handshake):
            self._process_handshake(obj)
        elif isinstance(obj, Protocol):
            self._decoded_records.append(obj)

    def _process_handshake(self, obj):
        if obj.message_seq != self._handshake_next_receive_seq:
            return

        self._handshake_msg_queue.append(obj)

        obj = self._handshake_msg_queue.pop(0)
        self._handshake_msg_queue = obj.concat(*self._handshake_msg_queue)

        if obj.is_fragment() is True:
            self._handshake_msg_queue.insert(0, obj)
            return

        obj.decode_payload()
        self._handshake_next_receive_seq += 1
        self._decoded_records.append(obj)

    def decode(self, data):
        while True and len(data) > 0:
            try:
                (obj, data) = RecordDTLSv10.decode(
                    data,
                    payload_auto_decode=False
                )
                (record, tmp_data) = RecordDTLSv10.decode_raw_payload(obj.content_type, obj.payload, payload_auto_decode=False)

                self._process(record)

            except NotEnoughData as e:
                print(e)
                break

    def is_empty(self):
        return len(self._decoded_records) == 0

    def pop_record(self):
        return self._decoded_records.pop(0)


class DTLSv10Connection(BaseDTLSConnection):
    pass

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
