import binascii

import pytest

from flextls.exception import NotEnoughData
from flextls.protocol.record import Record, RecordDTLSv1


class TestDTLSv10(object):
    def test_empty_data(self):
        with pytest.raises(NotEnoughData):
            RecordDTLSv1().decode(b"")

    def test_not_enough_data(self):
        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 0, Length 205
        data = binascii.unhexlify(b"16feff000000000000000000cd")
        with pytest.raises(NotEnoughData):
            RecordDTLSv1().decode(data)
        #
        assert binascii.hexlify(data) == b"16feff000000000000000000cd"


class TestClientHello(object):

    def test_pkg1(self):
        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 0, Length 205
        data = b"16feff000000000000000000cd"
        # Client Hello, Length 193, Message Sequence 0, Fragment Offset 0, Fragment Length 193
        data += b"010000c100000000000000c1"
        # DTLS 1.0
        data += b"feff"
        # Random
        data += b"24dc8f65fb5970f29af7f330b6a00942d71783db3230cba5bdb98213efdbb99f"
        # Session ID Length 0, Cookie Length 0
        data += b"0000"
        # Cipher Suites Length 78
        data += b"004e"
        # Cipher Suites 39
        data += b"c014c00a0039003800880087c00fc00500350084"
        data += b"c013c00900330032009a009900450044c00ec004"
        data += b"002f009600410007c012c00800160013c00dc003"
        data += b"000a001500120009001400110008000600ff"
        # Compression Methods Length 1: null
        data += b"0100"

        # Extensions, Length 73
        data += b"0049000b000403000102000a00340032000e000d"
        data += b"0019000b000c00180009000a0016001700080006"
        data += b"0007001400150004000500120013000100020003"
        data += b"000f0010001100230000000f000101"

        (record, data) = RecordDTLSv1().decode(binascii.unhexlify(data))

        assert record.content_type == 22

        assert record.version.major == 254
        assert record.version.minor == 255

        assert record.payload.type == 1

        assert record.payload.length == 193

        # Client Hello
        client_hello = record.payload.payload
        assert client_hello.version.major == 254
        assert client_hello.version.minor == 255

        assert len(client_hello.random.random_bytes) == 32

        assert len(client_hello.session_id) == 0

        assert len(client_hello.cipher_suites) == 39

        assert len(client_hello.compression_methods) == 1


    def test_pkg2(self):
        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 1, Length 225
        data = b"16feff000000000000000100e1"
        # Client Hello, Length 213, Message Sequence 1, Fragment Offset 0, Fragment Length 213
        data += b"010000d500010000000000d5"
        # DTLS 1.0
        data += b"feff"
        # Random
        data += b"24dc8f65fb5970f29af7f330b6a00942d71783db3230cba5bdb98213efdbb99f"
        # Session ID Length 0, Cookie Length 20, Cookie Data
        data += b"00142c24633bb13af58be4a0f50e47767cfa93e63515"
        # Cipher Suites Length 78
        data += b"004e"
        # Cipher Suites 39
        data += b"c014c00a0039003800880087c00fc00500350084"
        data += b"c013c00900330032009a009900450044c00ec004"
        data += b"002f009600410007c012c00800160013c00dc003"
        data += b"000a001500120009001400110008000600ff"
        # Compression Methods Length 1: null
        data += b"0100"
        # Extensions, Length 73
        data += b"0049000b000403000102000a00340032000e000d"
        data += b"0019000b000c00180009000a0016001700080006"
        data += b"0007001400150004000500120013000100020003"
        data += b"000f0010001100230000000f000101"

        (record, data) = RecordDTLSv1().decode(binascii.unhexlify(data))
        assert len(data) == 0

        assert record.content_type == 22

        assert record.version.major == 254
        assert record.version.minor == 255

        assert record.epoch == 0
        assert record.sequence_number == 1
        assert record.length == 225

        # Handshake
        handshake = record.payload
        assert handshake.type == 1
        assert handshake.length == 213
        assert handshake.message_seq == 1
        assert handshake.fragment_offset == 0
        assert handshake.fragment_length == 213

        # Client Hello
        client_hello = record.payload.payload
        assert client_hello.version.major == 254
        assert client_hello.version.minor == 255

        assert len(client_hello.random.random_bytes) == 32

        assert len(client_hello.session_id) == 0
        assert len(client_hello.cookie) == 20

        assert len(client_hello.cipher_suites) == 39

        assert len(client_hello.compression_methods) == 1

        assert len(client_hello.extensions) == 4


class TestHelloVerifyRequest(object):
    def test_pkg1(self):
        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 0, Length 35
        data = b"16feff00000000000000000023"

        # Hello Verify Request, Length 23, Message Sequence 0, Fragment Offset 0, Fragment Length 23
        data += b"030000170000000000000017"
        # DTLS 1.0
        data += b"feff"
        # Cookie Length: 20, Cockie (20 bytes)
        data += b"142c24633bb13af58be4a0f50e47767cfa93e63515"

        (record, data) = RecordDTLSv1().decode(binascii.unhexlify(data))

        assert len(data) == 0

        assert record.content_type == 22

        assert record.version.major == 254
        assert record.version.minor == 255

        assert record.length == 35

        assert record.payload.type == 3
        assert record.payload.length == 23

        assert record.payload.message_seq == 0
        assert record.payload.fragment_offset == 0
        assert record.payload.fragment_length == 23

        # Client Hello
        hello_verify = record.payload.payload
        assert hello_verify.version.major == 254
        assert hello_verify.version.minor == 255

        assert len(hello_verify.cookie) == 20


class TestServerHello(object):
    def test_pkg1(self):
        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 1, Length 74

        data = b"16feff0000000000000001004a"
        # Server Hello, Length 62, Message Sequence 1, Fragment Offset 0, Fragment Length 62
        data += b"0200003e000100000000003e"
        # DTLS 1.0
        data += b"feff"
        # Random
        data += b"0904c079eaf6fc8ccbb345bf1b279158d0127ec87bc2cf971c6c94ac42d1abd8"
        # Session ID Length 0, Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014), Compression Method: null (0)
        data += b"00c01400"
        # Extensions, Length 22
        data += b"0016ff01000100000b0004030001020023000000"
        data += b"0f000101"

        (record, data) = RecordDTLSv1().decode(binascii.unhexlify(data))
        assert len(data) == 0

        assert record.content_type == 22

        assert record.version.major == 254
        assert record.version.minor == 255

        assert record.epoch == 0
        assert record.sequence_number == 1
        assert record.length == 74

        # Handshake
        handshake = record.payload
        assert handshake.type == 2
        assert handshake.length == 62
        assert handshake.message_seq == 1
        assert handshake.fragment_offset == 0
        assert handshake.fragment_length == 62

        # Server Hello
        server_hello = record.payload.payload
        assert server_hello.version.major == 254
        assert server_hello.version.minor == 255

        assert len(server_hello.random.random_bytes) == 32

        assert len(server_hello.session_id) == 0

        # ToDo: test cipher suite and compression

        assert len(server_hello.extensions) == 4