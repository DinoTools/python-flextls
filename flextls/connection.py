"""
The class in this python module can be used to handle SSL/TLS/DTLS connections.
"""
from flextls import helper
from flextls.protocol import Protocol
from flextls.protocol.record import RecordDTLSv10
from flextls.protocol.handshake import DTLSv10Handshake
from flextls.exception import NotEnoughData
from flextls.exception import NotEnoughData, WrongProtocolVersion
from flextls.protocol.record import RecordSSLv3
from flextls.protocol.handshake import Handshake


class BaseConnection(object):
    """
    Base class to handle SSL/TLS/DTLS connections and its state.
    """
    def __init__(self, protocol_version):
        self._decoded_records = []
        self._cur_protocol_version = protocol_version

    def clear_records(self):
        self._decoded_records.clear()

    def decode(self, data):
        raise NotImplementedError

    def encode(self, records):
        raise NotImplementedError

    def is_empty(self):
        return len(self._decoded_records) == 0

    def pop_record(self):
        return self._decoded_records.pop(0)


class BaseDTLSConnection(BaseConnection):
    """
    Base class for DTLS connections.
    """
    def __init__(self, protocol_version):
        BaseConnection.__init__(self, protocol_version=protocol_version)
        self._window = []
        self._window_next_seq = 0

        for i in range(0, 64):
            self._window.append(None)

        self._handshake_next_receive_seq = 0
        self._handshake_next_send_seq = 0
        self._handshake_msg_queue = []

        self._record_next_receive_seq = 0
        self._record_next_send_seq = 0
        self._epoch = 0

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

                version = helper.get_version_by_version_id((
                    obj.version.major,
                    obj.version.minor
                ))

                if version != self._cur_protocol_version:
                    # ToDo: Save data before exit?
                    raise WrongProtocolVersion(
                        record=obj
                    )
                (record, tmp_data) = RecordDTLSv10.decode_raw_payload(obj.content_type, obj.payload, payload_auto_decode=False)

                self._process(record)

            except NotEnoughData as e:
                print(e)
                break

    def encode(self, records):
        if isinstance(records, Protocol):
            records = [records]

        pkgs = []
        for record in records:
            if not isinstance(record, Protocol):
                raise TypeError("Record must be of type flextls.protocol.Protocol()")

            if isinstance(record, DTLSv10Handshake):
                record.message_seq = self._handshake_next_send_seq
                self._handshake_next_send_seq += 1

            dtls_record = RecordDTLSv10()
            ver_major, ver_minor = helper.get_tls_version(self._cur_protocol_version)
            dtls_record.version.major = ver_major
            dtls_record.version.minor = ver_minor
            dtls_record.set_payload(record)
            dtls_record.epoch = self._epoch
            dtls_record.sequence_number = self._record_next_send_seq

            pkgs.append(dtls_record.encode())
            self._record_next_send_seq += 1

        return pkgs

    def is_empty(self):
        return len(self._decoded_records) == 0

    def pop_record(self):
        return self._decoded_records.pop(0)


class DTLSv10Connection(BaseDTLSConnection):
    """
    Class to handle DTLS 1.0 and DTLS 1.2 connections.
    """
    pass


class BaseTLSConnection(BaseConnection):
    """
    Class to handle SSL/TLS connections.
    """
    def __init__(self, protocol_version):
        BaseConnection.__init__(self, protocol_version=protocol_version)
        self._raw_stream_data = b""

        self._cur_record_type = None
        self._cur_record_data = b""

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

    def decode(self, data):
        self._raw_stream_data += data
        while True:
            try:
                (obj, data) = RecordSSLv3.decode(
                    self._raw_stream_data,
                    payload_auto_decode=False
                )
                version = helper.get_version_by_version_id((
                    obj.version.major,
                    obj.version.minor
                ))

                self._raw_stream_data = data

                if version != self._cur_protocol_version:
                    raise WrongProtocolVersion(
                        record=obj
                    )

                if self._cur_record_type is None:
                    self._cur_record_type = obj.content_Type

                if self._cur_record_type != obj.content_type:
                    self._decode_record_payload()
                    self._cur_record_data = b""
                    self._cur_record_type = obj.content_type

                self._cur_record_data += obj.payload

                self._decode_record_payload()

            except NotEnoughData:
                break

    def encode(self, records):
        if isinstance(records, Protocol):
            records = [records]

        pkgs = []
        for record in records:
            if isinstance(record, Protocol):
                tls_record = RecordSSLv3()
                ver_major, ver_minor = helper.get_tls_version(self._cur_protocol_version)
                tls_record.version.major = ver_major
                tls_record.version.minor = ver_minor
                tls_record.set_payload(record)
                pkgs.append(tls_record.encode())
            else:
                raise TypeError("Record must be of type flextls.protocol.Protocol()")

        return pkgs


class SSLv30Connection(BaseTLSConnection):
    """
    Class to handle SSLv3.0, TLS 1.0, TLS 1.1 and TLS 1.2 connections.
    """
    pass
