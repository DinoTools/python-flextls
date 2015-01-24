import binascii

import pytest

from flextls.exception import NotEnoughData
from flextls.protocol.record import Record, RecordDTLSv10


class TestDTLSv10(object):
    def test_empty_data(self):
        with pytest.raises(NotEnoughData):
            RecordDTLSv10().decode(b"")

    def test_not_enough_data(self):
        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 0, Length 205
        data = binascii.unhexlify(b"16feff000000000000000000cd")
        with pytest.raises(NotEnoughData):
            RecordDTLSv10().decode(data)
        #
        assert binascii.hexlify(data) == b"16feff000000000000000000cd"


class TestCertificate(object):
    def test_pkg1(self):

        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 2, Length 696
        data = b"16feff000000000000000202b8"
        # Certificate, Length 684, Message Sequence 2, Fragment Offset 0, Fragment Length 684
        data += b"0b0002ac00020000000002ac"
        # Certificate Length: 681, Certificate Data
        data += b"0002a90002a6308202a23082020ba003020102020900e8ffa7c3bdac30"
        data += b"81300d06092a864886f70d0101050500306a310b300906035504061302"
        data += b"44453110300e06035504080c075361636873656e31143012060355040a"
        data += b"0c0b4578616d706c6520496e633112301006035504030c096c6f63616c"
        data += b"686f7374311f301d06092a864886f70d01090116106365727440657861"
        data += b"6d706c652e6f7267301e170d3135303131303037333733345a170d3136"
        data += b"303131303037333733345a306a310b3009060355040613024445311030"
        data += b"0e06035504080c075361636873656e31143012060355040a0c0b457861"
        data += b"6d706c6520496e633112301006035504030c096c6f63616c686f737431"
        data += b"1f301d06092a864886f70d010901161063657274406578616d706c652e"
        data += b"6f726730819f300d06092a864886f70d010101050003818d0030818902"
        data += b"818100a742a7933fd1877d8596a8c99d36009502ce0e6bea07b5b2de31"
        data += b"bd39a62177475ed73b3439166845e5d48199391d9fd0a90997d0790744"
        data += b"a4748ea271ed301920898b5b5a7d0c4d91c0fc06c1585ed2e050c8b7c7"
        data += b"8eef239fdcdbcf91510e52d862beb839d80e4bc431c290f0da89960bf2"
        data += b"0c655a201bdaf768478f2e22539f050203010001a350304e301d060355"
        data += b"1d0e0416041487dca658f477a8be358453feb61c796d6a6c5b5d301f06"
        data += b"03551d2304183016801487dca658f477a8be358453feb61c796d6a6c5b"
        data += b"5d300c0603551d13040530030101ff300d06092a864886f70d01010505"
        data += b"00038181003d1dfb7cdd46b2fb8b1d3fa18207634056ddfae8fc5e3ce7"
        data += b"24a1dd0d154f73d885711024322cfd88871156807061bffa15378fe341"
        data += b"d4b91773cdba279645458af6fc3511fc613c284bc36e69559428c6b8a9"
        data += b"4cc674399bc69dc8c2e673ea709638320bdd98d0a3c4b7a94e31184e27"
        data += b"e75c4273543b02a6ca1151b8a4bb03da79"

        (record, data) = RecordDTLSv10().decode(binascii.unhexlify(data))
        assert len(data) == 0

        assert record.content_type == 22

        assert record.version.major == 254
        assert record.version.minor == 255

        assert record.epoch == 0
        assert record.sequence_number == 2
        assert record.length == 696

        # Handshake
        handshake = record.payload
        assert handshake.type == 11
        assert handshake.length == 684
        assert handshake.message_seq == 2
        assert handshake.fragment_offset == 0
        assert handshake.fragment_length == 684

        # Certificate
        certificate = record.payload.payload
        assert len(certificate.certificate_list) == 1
        assert len(certificate.certificate_list[0].value) == 678


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

        (record, data) = RecordDTLSv10().decode(binascii.unhexlify(data))

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

        (record, data) = RecordDTLSv10().decode(binascii.unhexlify(data))
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


class TestClientKeyExchange(object):
    def test_pkg1(self):

        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 2, Length 78
        data = b"16feff0000000000000002004e"

        # Client Key Exchange, Length 66, Message Sequence 2, Fragment Offset 0, Fragment Length 66
        data += b"100000420002000000000042"

        # Pubkey Length: 65
        data += b"41"
        # Pubkey
        data += b"0466c160c0cc7a657c0dbd19be373922ffed1e78315706332c17ccb79b" \
                b"3b7d9050fd55bc74c37f36a8d4c6773b95314fe268e0385e490ef73079" \
                b"c405f54c61265e"

        (record, data) = RecordDTLSv10().decode(binascii.unhexlify(data))
        assert len(data) == 0

        assert record.content_type == 22

        assert record.version.major == 254
        assert record.version.minor == 255

        assert record.epoch == 0
        assert record.sequence_number == 2
        assert record.length == 78

        # Handshake
        handshake = record.payload
        assert handshake.type == 16
        assert handshake.length == 66
        assert handshake.message_seq == 2
        assert handshake.fragment_offset == 0
        assert handshake.fragment_length == 66

        # Server Key Exchange
        key_exchange = record.payload.payload


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

        (record, data) = RecordDTLSv10().decode(binascii.unhexlify(data))

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

        (record, data) = RecordDTLSv10().decode(binascii.unhexlify(data))
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


class TestServerHelloDone(object):
    def test_pkg1(self):
        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 4, Length 12
        data = b"16feff0000000000000004000c"

        # Server Hello Done, Length 12, Message Sequence 4, Fragment Offset 0, Fragment Length 0
        data += b"0e0000000004000000000000"

        (record, data) = RecordDTLSv10().decode(binascii.unhexlify(data))
        assert len(data) == 0

        assert record.content_type == 22

        assert record.version.major == 254
        assert record.version.minor == 255

        assert record.epoch == 0
        assert record.sequence_number == 4
        assert record.length == 12

        # Handshake
        handshake = record.payload
        assert handshake.type == 14
        assert handshake.length == 0
        assert handshake.message_seq == 4
        assert handshake.fragment_offset == 0
        assert handshake.fragment_length == 0


class TestServerKeyExchange(object):
    def test_pkg1(self):

        # Handshake, DTLSv1.0, Epoch 0, Sequence Number 3, Length 211
        data = b"16feff000000000000000300d3"

        # Server Key Exchange, Length 199, Message Sequence 3, Fragment Offset 0, Fragment Length 199
        data += b"0c0000c700030000000000c7"
        # Curve Type: named_curve (0x03), Named Curve: secp256r1 (0x0017)
        data += b"030017"

        # Pubkey Length: 65
        data += b"41"
        # Pubkey
        data += b"0407220baac1ab19e1bcf6151a86a9e6c6d8f35b6bc034b9f6b26d8a82" \
                b"6f9081c57f7038f66c1e9473e96310194cd71609038a5d1425951e857a" \
                b"ee8d61e4a657d9"

        # Signature Length: 128
        data += b"0080"
        # Signature
        data += b"877afeccec9b09ecf17c637be672367f8a12127af39e5f4a93ced4989e" \
                b"5fb213a4e99418480b54e5aac1f56865510620c1ae6bdcfad22511089a" \
                b"053552b7da770b252e993c45a6354fc4d7bfdb844d1fa8748a22057a2a" \
                b"8e38410c5ef6bec7acf6eda364c3d0afdddaef7b6d9745dc514bcb7241" \
                b"0468624094790cf054475dd6"

        (record, data) = RecordDTLSv10().decode(binascii.unhexlify(data))
        assert len(data) == 0

        assert record.content_type == 22

        assert record.version.major == 254
        assert record.version.minor == 255

        assert record.epoch == 0
        assert record.sequence_number == 3
        assert record.length == 211

        # Handshake
        handshake = record.payload
        assert handshake.type == 12
        assert handshake.length == 199
        assert handshake.message_seq == 3
        assert handshake.fragment_offset == 0
        assert handshake.fragment_length == 199

        # Server Key Exchange
        key_exchange = record.payload.payload
