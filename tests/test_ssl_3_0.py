import binascii

import pytest

import flextls
from flextls.exception import NotEnoughData
from flextls.protocol.record import Record, RecordSSLv3
from flextls import TLSv10Connection


class TestSSLv3(object):
    def test_empty_data(self):
        with pytest.raises(NotEnoughData):
            RecordSSLv3().decode(b"")

    def test_not_enough_data(self):
        # Handshake, SSLv3.0, Length 136
        data = binascii.unhexlify(b"1603000088")
        with pytest.raises(NotEnoughData):
            RecordSSLv3().decode(data)
        #
        assert binascii.hexlify(data) == b"1603000088"


class TestClientHello(object):

    def _get_record(self):
        # Handshake, SSLv3.0, Length 136
        data = b"1603000088"
        # Client Hello, Length 132, SSLv3.0
        data += b"010000840300"
        # Random
        data += b"0a629b0e415bb5c62ba473e0d9c14b75b189039413669a9457eb2bada593a408"
        # Session ID
        data += b"00"
        # Cipher Suites Length 92
        data += b"005c"
        # Cipher Suites 46
        data += b"c014c00a0039003800880087c00fc00500350084"
        data += b"c013c00900330032009a009900450044c00ec004"
        data += b"002f009600410007c011c007c00cc00200050004"
        data += b"c012c00800160013c00dc003000a001500120009"
        data += b"0014001100080006000300ff"
        # Compression Methods Length 2: Deflate, null
        data += b"020100"

        (record, data) = Record().decode(binascii.unhexlify(data))
        return record

    def test_record_content_type(self):
        record = self._get_record()
        assert record.content_type == 22

    def test_record_version(self):
        record = self._get_record()
        assert record.version.major == 3
        assert record.version.minor == 0

    def test_handshake_type(self):
        record = self._get_record()
        assert record.payload.type == 1

    def test_handshake_length(self):
        record = self._get_record()
        assert record.payload.length == 132

    def test_client_hello_version(self):
        record = self._get_record()
        assert record.payload.payload.version.major == 3
        assert record.payload.payload.version.minor == 0

    def test_client_hello_random(self):
        record = self._get_record()
        assert len(record.payload.payload.random.random_bytes) == 32

    def test_client_hello_session_id(self):
        record = self._get_record()
        print(record.payload.payload)
        assert len(record.payload.payload.session_id) == 0

    def test_client_hello_cipher_suites(self):
        record = self._get_record()
        assert len(record.payload.payload.cipher_suites) == 46

    def test_client_hello_compression_methods(self):
        record = self._get_record()
        assert len(record.payload.payload.compression_methods) == 2


class TestClientHello2(object):

    def test_get_record(self):
        con = TLSv10Connection(
            protocol_version=flextls.registry.version.SSLv30
        )

        data = b""
        # Client Hello, Length 132, SSLv3.0
        data += b"010000840300"
        # Random
        data += b"0a629b0e415bb5c62ba473e0d9c14b75b189039413669a9457eb2bada593a408"
        # Session ID
        data += b"00"
        # Cipher Suites Length 92
        data += b"005c"
        # Cipher Suites 46
        data += b"c014c00a0039003800880087c00fc00500350084"
        data += b"c013c00900330032009a009900450044c00ec004"
        data += b"002f009600410007c011c007c00cc00200050004"
        data += b"c012c00800160013c00dc003000a001500120009"
        data += b"0014001100080006000300ff"
        # Compression Methods Length 2: Deflate, null
        data += b"020100"

        n = 50
        data_splited = [data[i:i + n] for i in range(0, len(data), n)]

        # Handshake, SSLv3.0, Length 136
        for part in data_splited:
            l = "%.2x" % len(part)
            data = b"16030000" + l.encode('ascii') + part
            con.decode(data)

        # (record, data) = Record().decode(binascii.unhexlify(data))
        #return record


class TestServerHello(object):

    def _get_record(self):
        # Handshake, SSLv3.0, Length 81
        data = b"1603000051"
        # Server Hello, Length 77, SSLv3.0
        data += b"0200004d0300"
        # Random
        data += b"5422c711caee59ab1f2146234b5b6a17fb34177605a02852952d8321f9b234d8"
        # Session ID Length 32, Data
        data += b"20432d044d99d74289eb663a0eb347e752b1683cf90a409c5f8673b98fb197cde9"
        # Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
        data += b"0039"
        # Compression Method: null (0)
        data += b"00"
        # Extensions Length: 5
        data += b"0005"
        # renegotiation_info (0xff01), length 1, reneg info length 0
        data += b"ff01000100"

        (record, data) = Record().decode(binascii.unhexlify(data))
        return record

    def test_record_content_type(self):
        record = self._get_record()
        assert record.content_type == 22

    def test_record_version(self):
        record = self._get_record()
        assert record.version.major == 3
        assert record.version.minor == 0

    def test_record_length(self):
        record = self._get_record()
        assert record.length == 81

    def test_handshake_type(self):
        record = self._get_record()
        assert record.payload.type == 2

    def test_handshake_length(self):
        record = self._get_record()
        assert record.payload.length == 77

    def test_client_hello_version(self):
        record = self._get_record()
        assert record.payload.payload.version.major == 3
        assert record.payload.payload.version.minor == 0

    def test_client_hello_random(self):
        record = self._get_record()
        assert len(record.payload.payload.random.random_bytes) == 32

    def test_client_hello_session_id(self):
        record = self._get_record()
        assert len(record.payload.payload.session_id) == 32

    def test_client_hello_cipher_suite(self):
        record = self._get_record()
        assert record.payload.payload.cipher_suite == 0x0039

    def test_client_hello_compression_methods(self):
        record = self._get_record()
        assert record.payload.payload.compression_method == 0

    def test_client_hello_extensions(self):
        record = self._get_record()
        assert len(record.payload.payload.extensions) == 1

    def test_extension_renegotiation_info_type(self):
        record = self._get_record()
        ext = record.payload.payload.extensions[0]
        assert ext.type == 0xff01

    def test_extension_renegotiation_info_length(self):
        record = self._get_record()
        ext = record.payload.payload.extensions[0]
        assert ext.length == 1


class TestCertificate(object):

    def _get_record(self):
        # Handshake, SSLv3.0, Length 848
        data = b"160300034d"
        # Certificate, Length 841
        data += b"0b000349"
        # Certificates Length: 838
        data += b"000346"
        # Certificate 1 Length 835
        data += b"000343"
        # Certificate 1 Data
        data += b"3082033f308202a8a00302010202024ae6300d06"
        data += b"092a864886f70d01010505003081bb310b300906"
        data += b"0355040613022d2d3112301006035504080c0953"
        data += b"6f6d6553746174653111300f06035504070c0853"
        data += b"6f6d654369747931193017060355040a0c10536f"
        data += b"6d654f7267616e697a6174696f6e311f301d0603"
        data += b"55040b0c16536f6d654f7267616e697a6174696f"
        data += b"6e616c556e6974311e301c06035504030c156c6f"
        data += b"63616c686f73742e6c6f63616c646f6d61696e31"
        data += b"29302706092a864886f70d010901161a726f6f74"
        data += b"406c6f63616c686f73742e6c6f63616c646f6d61"
        data += b"696e301e170d3134303530343035343935345a17"
        data += b"0d3135303530343035343935345a3081bb310b30"
        data += b"09060355040613022d2d3112301006035504080c"
        data += b"09536f6d6553746174653111300f06035504070c"
        data += b"08536f6d654369747931193017060355040a0c10"
        data += b"536f6d654f7267616e697a6174696f6e311f301d"
        data += b"060355040b0c16536f6d654f7267616e697a6174"
        data += b"696f6e616c556e6974311e301c06035504030c15"
        data += b"6c6f63616c686f73742e6c6f63616c646f6d6169"
        data += b"6e3129302706092a864886f70d010901161a726f"
        data += b"6f74406c6f63616c686f73742e6c6f63616c646f"
        data += b"6d61696e30819f300d06092a864886f70d010101"
        data += b"050003818d0030818902818100b712157298a96c"
        data += b"4f64027fec7fc42f66f5d5d46da4096b5f0b8e77"
        data += b"9b5677dcecba2eb8bca41b11eda4ee5f19d86cbb"
        data += b"714d0a38a34c0bc7b02ec3594c56b1b5aea33d3f"
        data += b"2de966b3f7256594b990fa7c0de34d99d9d8a0a6"
        data += b"26b49a0234822a17868316e25aa58febd2369374"
        data += b"4a8bf0836fe5d337b6caebeaef0b583758340f4a"
        data += b"d10203010001a350304e301d0603551d0e041604"
        data += b"149744e81ba93cd6eec904f7da99100b1e6c37e4"
        data += b"29301f0603551d230418301680149744e81ba93c"
        data += b"d6eec904f7da99100b1e6c37e429300c0603551d"
        data += b"13040530030101ff300d06092a864886f70d0101"
        data += b"0505000381810032e346b65873c17df9b86d61fb"
        data += b"2692255a4654861cf77ddc82feb03827f6074f9f"
        data += b"2671033abc6d6f3d4cdc41545bee1ff7e0d94d59"
        data += b"d70e9f8150e63aee5f0ffe3c7b3cfd053ac19912"
        data += b"54284376b5063637fd8aee38c9b2ca1ec5c49c45"
        data += b"d27038474f393f2dc0233d72afa769085ffe7e4d"
        data += b"46363525ce04b9cb4d6e88b9595394"

        (record, data) = Record().decode(binascii.unhexlify(data))
        return record

    def test_record_content_type(self):
        record = self._get_record()
        assert record.content_type == 22

    def test_record_version(self):
        record = self._get_record()
        assert record.version.major == 3
        assert record.version.minor == 0

    def test_record_length(self):
        record = self._get_record()
        assert record.length == 845

    def test_handshake_type(self):
        record = self._get_record()
        assert record.payload.type == 11

    def test_handshake_length(self):
        record = self._get_record()
        assert record.payload.length == 841

    def test_certificate_count(self):
        record = self._get_record()
        assert len(record.payload.payload.certificate_list) == 1

    def test_certificate_count(self):
        record = self._get_record()
        assert len(record.payload.payload.certificate_list[0].value) == 835


class TestServerKeyExchange(object):

    def _get_record(self):
        # Handshake, SSLv3.0, Length 397
        data = b"160300018d"
        # Server Key Exchange, Length 393
        data += b"0c000189"

        # Diffie-Hellman Server Params
        data += b"0080d67de440cbbbdc1936d693d34afd0ad50c84"
        data += b"d239a45f520bb88174cb98bce951849f912e639c"
        data += b"72fb13b4b4d7177e16d55ac179ba420b2a29fe32"
        data += b"4a467a635e81ff5901377beddcfd33168a461aad"
        data += b"3b72dae8860078045b07a7dbca7874087d1510ea"
        data += b"9fcc9ddd330507dd62db88aeaa747de0f4d6e2bd"
        data += b"68b0e7393e0f24218eb300010200807f60577736"
        data += b"507e421a116231d6d1143a3c142cac90eb99c2ba"
        data += b"44ea68d7e8bb2d03835d66830015d86179d354b5"
        data += b"1c2184085e363e12ed54075668669dc4cf3a2f30"
        data += b"8899d22ed1953b8f2c677532120607ffb0b79da1"
        data += b"88a4c528de79ede99081cb8147cda8fa40cdf663"
        data += b"33cbeb83c0f4204eb99e95be142d55da7773d6f5"
        data += b"af8e4500808d9ecd6ca8eba93ad44fb0901beba6"
        data += b"fe058afe3fd63a33869eba477ed37e7f3d1ac73b"
        data += b"37fe547049cd52b2115af8099dccd55455169902"
        data += b"b17228727a7d48b838a769e383b0fa73b1484641"
        data += b"68c431cf2765eecc35a5b7071b46ae967999ed30"
        data += b"85d4214190dcc947b8f0005f65eb79e6fde7daa9"
        data += b"9789fd18c077b4d98200a13b53"

        (record, data) = Record().decode(binascii.unhexlify(data))
        return record

    def test_record_content_type(self):
        record = self._get_record()
        assert record.content_type == 22

    def test_record_version(self):
        record = self._get_record()
        assert record.version.major == 3
        assert record.version.minor == 0

    def test_record_length(self):
        record = self._get_record()
        assert record.length == 397

    def test_handshake_type(self):
        record = self._get_record()
        assert record.payload.type == 12

    def test_handshake_length(self):
        record = self._get_record()
        assert record.payload.length == 393


class TestServerHelloDone(object):

    def _get_record(self):
        # Handshake, SSLv3.0, Length 4
        data = b"1603000004"
        # Server Hello Done, Length 0
        data += b"0e000000"

        (record, data) = Record().decode(binascii.unhexlify(data))
        return record

    def test_record_content_type(self):
        record = self._get_record()
        assert record.content_type == 22

    def test_record_version(self):
        record = self._get_record()
        assert record.version.major == 3
        assert record.version.minor == 0

    def test_record_length(self):
        record = self._get_record()
        assert record.length == 4

    def test_handshake_type(self):
        record = self._get_record()
        assert record.payload.type == 14

    def test_handshake_length(self):
        record = self._get_record()
        assert record.payload.length == 0


class TestClientKeyExchange(object):

    def _get_record(self):
        # Handshake, SSLv3.0, Length 134
        data = b"1603000086"
        # Client Key Exchange, Length 130
        data += b"10000082"

        # Diffie-Hellman Client Params
        # Length 128
        data += b"0080"
        # Data
        data += b"051c7b342406712e6805703ac28edde15506f083"
        data += b"f67018b8d868fd16cd2bb4b4105b8c05fac977ac"
        data += b"c913892317a49d776377d3e5a17828f053dc8a79"
        data += b"c8a4189847c6145b6ded2422703e176bca8bd512"
        data += b"da7631fbc12a7740d9a8216214e3549b51450362"
        data += b"dfd40c5fb1a9f9be125374ada9fe221c2ea74fda"
        data += b"621896d6b3df8432"

        (record, data) = Record().decode(binascii.unhexlify(data))
        return record

    def test_record_content_type(self):
        record = self._get_record()
        assert record.content_type == 22

    def test_record_version(self):
        record = self._get_record()
        assert record.version.major == 3
        assert record.version.minor == 0

    def test_record_length(self):
        record = self._get_record()
        assert record.length == 134

    def test_handshake_type(self):
        record = self._get_record()
        assert record.payload.type == 16

    def test_handshake_length(self):
        record = self._get_record()
        assert record.payload.length == 130


class TestChangeCipherSpec(object):

    def _get_record(self):
        # Change Cipher Spec, SSLv3.0, Length 1
        data = b"1403000001"
        # Change Cipher Spec Message
        data += b"01"

        (record, data) = Record().decode(binascii.unhexlify(data))
        return record

    def test_record_content_type(self):
        record = self._get_record()
        assert record.content_type == 20

    def test_record_version(self):
        record = self._get_record()
        assert record.version.major == 3
        assert record.version.minor == 0

    def test_record_length(self):
        record = self._get_record()
        assert record.length == 1

    def test_change_cipher_spechandshake_type(self):
        record = self._get_record()
        assert record.payload.type == 1
