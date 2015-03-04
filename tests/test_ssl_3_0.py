import binascii

import pytest

import flextls
from flextls.connection import SSLv30Connection
from flextls.exception import NotEnoughData
from flextls.protocol.record import Record, SSLv3Record
from flextls.protocol.handshake import Handshake

client_hello_01 = b""
# Client Hello, Length 132, SSLv3.0
client_hello_01 += b"010000840300"
# Random
client_hello_01 += b"0a629b0e415bb5c62ba473e0d9c14b75b189039413669a9457eb2bada593a408"
# Session ID
client_hello_01 += b"00"
# Cipher Suites Length 92
client_hello_01 += b"005c"
# Cipher Suites 46
client_hello_01 += b"c014c00a0039003800880087c00fc00500350084"
client_hello_01 += b"c013c00900330032009a009900450044c00ec004"
client_hello_01 += b"002f009600410007c011c007c00cc00200050004"
client_hello_01 += b"c012c00800160013c00dc003000a001500120009"
client_hello_01 += b"0014001100080006000300ff"
# Compression Methods Length 2: Deflate, null
client_hello_01 += b"020100"

client_key_exchange_01 = b""
# Client Key Exchange, Length 130
client_key_exchange_01 += b"10000082"
# Diffie-Hellman Client Params
# Length 128
client_key_exchange_01 += b"0080"
# Data
client_key_exchange_01 += b"051c7b342406712e6805703ac28edde15506f083"
client_key_exchange_01 += b"f67018b8d868fd16cd2bb4b4105b8c05fac977ac"
client_key_exchange_01 += b"c913892317a49d776377d3e5a17828f053dc8a79"
client_key_exchange_01 += b"c8a4189847c6145b6ded2422703e176bca8bd512"
client_key_exchange_01 += b"da7631fbc12a7740d9a8216214e3549b51450362"
client_key_exchange_01 += b"dfd40c5fb1a9f9be125374ada9fe221c2ea74fda"
client_key_exchange_01 += b"621896d6b3df8432"

server_hello_01 = b""
# Server Hello, Length 77, SSLv3.0
server_hello_01 += b"0200004d0300"
# Random
server_hello_01_randmon = b"5422c711caee59ab1f2146234b5b6a17fb34177605a02852952d8321f9b234d8"
server_hello_01 += server_hello_01_randmon
# Session ID Length 32, Data
server_hello_01 += b"20432d044d99d74289eb663a0eb347e752b1683cf90a409c5f8673b98fb197cde9"
# Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
server_hello_01 += b"0039"
# Compression Method: null (0)
server_hello_01 += b"00"
# Extensions Length: 5
server_hello_01 += b"0005"
# renegotiation_info (0xff01), length 1, reneg info length 0
server_hello_01 += b"ff01000100"

server_certificate_01 = b""
# Certificate, Length 841
server_certificate_01 += b"0b000349"
# Certificates Length: 838
server_certificate_01 += b"000346"
# Certificate 1 Length 835
server_certificate_01 += b"000343"
# Certificate 1 Data
server_certificate_01 += b"3082033f308202a8a00302010202024ae6300d06"
server_certificate_01 += b"092a864886f70d01010505003081bb310b300906"
server_certificate_01 += b"0355040613022d2d3112301006035504080c0953"
server_certificate_01 += b"6f6d6553746174653111300f06035504070c0853"
server_certificate_01 += b"6f6d654369747931193017060355040a0c10536f"
server_certificate_01 += b"6d654f7267616e697a6174696f6e311f301d0603"
server_certificate_01 += b"55040b0c16536f6d654f7267616e697a6174696f"
server_certificate_01 += b"6e616c556e6974311e301c06035504030c156c6f"
server_certificate_01 += b"63616c686f73742e6c6f63616c646f6d61696e31"
server_certificate_01 += b"29302706092a864886f70d010901161a726f6f74"
server_certificate_01 += b"406c6f63616c686f73742e6c6f63616c646f6d61"
server_certificate_01 += b"696e301e170d3134303530343035343935345a17"
server_certificate_01 += b"0d3135303530343035343935345a3081bb310b30"
server_certificate_01 += b"09060355040613022d2d3112301006035504080c"
server_certificate_01 += b"09536f6d6553746174653111300f06035504070c"
server_certificate_01 += b"08536f6d654369747931193017060355040a0c10"
server_certificate_01 += b"536f6d654f7267616e697a6174696f6e311f301d"
server_certificate_01 += b"060355040b0c16536f6d654f7267616e697a6174"
server_certificate_01 += b"696f6e616c556e6974311e301c06035504030c15"
server_certificate_01 += b"6c6f63616c686f73742e6c6f63616c646f6d6169"
server_certificate_01 += b"6e3129302706092a864886f70d010901161a726f"
server_certificate_01 += b"6f74406c6f63616c686f73742e6c6f63616c646f"
server_certificate_01 += b"6d61696e30819f300d06092a864886f70d010101"
server_certificate_01 += b"050003818d0030818902818100b712157298a96c"
server_certificate_01 += b"4f64027fec7fc42f66f5d5d46da4096b5f0b8e77"
server_certificate_01 += b"9b5677dcecba2eb8bca41b11eda4ee5f19d86cbb"
server_certificate_01 += b"714d0a38a34c0bc7b02ec3594c56b1b5aea33d3f"
server_certificate_01 += b"2de966b3f7256594b990fa7c0de34d99d9d8a0a6"
server_certificate_01 += b"26b49a0234822a17868316e25aa58febd2369374"
server_certificate_01 += b"4a8bf0836fe5d337b6caebeaef0b583758340f4a"
server_certificate_01 += b"d10203010001a350304e301d0603551d0e041604"
server_certificate_01 += b"149744e81ba93cd6eec904f7da99100b1e6c37e4"
server_certificate_01 += b"29301f0603551d230418301680149744e81ba93c"
server_certificate_01 += b"d6eec904f7da99100b1e6c37e429300c0603551d"
server_certificate_01 += b"13040530030101ff300d06092a864886f70d0101"
server_certificate_01 += b"0505000381810032e346b65873c17df9b86d61fb"
server_certificate_01 += b"2692255a4654861cf77ddc82feb03827f6074f9f"
server_certificate_01 += b"2671033abc6d6f3d4cdc41545bee1ff7e0d94d59"
server_certificate_01 += b"d70e9f8150e63aee5f0ffe3c7b3cfd053ac19912"
server_certificate_01 += b"54284376b5063637fd8aee38c9b2ca1ec5c49c45"
server_certificate_01 += b"d27038474f393f2dc0233d72afa769085ffe7e4d"
server_certificate_01 += b"46363525ce04b9cb4d6e88b9595394"

server_key_exchange_01 = b""
# Server Key Exchange, Length 393
server_key_exchange_01 += b"0c000189"

# Diffie-Hellman Server Params
server_key_exchange_01 += b"0080d67de440cbbbdc1936d693d34afd0ad50c84"
server_key_exchange_01 += b"d239a45f520bb88174cb98bce951849f912e639c"
server_key_exchange_01 += b"72fb13b4b4d7177e16d55ac179ba420b2a29fe32"
server_key_exchange_01 += b"4a467a635e81ff5901377beddcfd33168a461aad"
server_key_exchange_01 += b"3b72dae8860078045b07a7dbca7874087d1510ea"
server_key_exchange_01 += b"9fcc9ddd330507dd62db88aeaa747de0f4d6e2bd"
server_key_exchange_01 += b"68b0e7393e0f24218eb300010200807f60577736"
server_key_exchange_01 += b"507e421a116231d6d1143a3c142cac90eb99c2ba"
server_key_exchange_01 += b"44ea68d7e8bb2d03835d66830015d86179d354b5"
server_key_exchange_01 += b"1c2184085e363e12ed54075668669dc4cf3a2f30"
server_key_exchange_01 += b"8899d22ed1953b8f2c677532120607ffb0b79da1"
server_key_exchange_01 += b"88a4c528de79ede99081cb8147cda8fa40cdf663"
server_key_exchange_01 += b"33cbeb83c0f4204eb99e95be142d55da7773d6f5"
server_key_exchange_01 += b"af8e4500808d9ecd6ca8eba93ad44fb0901beba6"
server_key_exchange_01 += b"fe058afe3fd63a33869eba477ed37e7f3d1ac73b"
server_key_exchange_01 += b"37fe547049cd52b2115af8099dccd55455169902"
server_key_exchange_01 += b"b17228727a7d48b838a769e383b0fa73b1484641"
server_key_exchange_01 += b"68c431cf2765eecc35a5b7071b46ae967999ed30"
server_key_exchange_01 += b"85d4214190dcc947b8f0005f65eb79e6fde7daa9"
server_key_exchange_01 += b"9789fd18c077b4d98200a13b53"

server_hello_done_01 = b"0e000000"


def prepare_handshake_data(data):
    # Handshake, SSLv3.0
    result = b"160300"
    # Length
    tmp_len = "%.4x" % (len(data) / 2)
    result += tmp_len.encode("ascii")
    result += data
    return binascii.unhexlify(result)


def prepare_handshake_data_split(data, part_len):
    results = []

    # We split hex data
    part_len = part_len * 2

    for i in range(0, len(data), part_len):
        part = data[i:i + part_len]
        l = "%.4x" % (len(part) / 2)
        # Handshake, SSLv3.0
        results.append(
            binascii.unhexlify(
                b"160300" + l.encode('ascii') + part
            )
        )
    return results


class TestSSLv3(object):
    def test_empty_data(self):
        with pytest.raises(NotEnoughData):
            SSLv3Record().decode(b"")

    def test_not_enough_data(self):
        # Handshake, SSLv3.0, Length 136
        data = binascii.unhexlify(b"1603000088")
        with pytest.raises(NotEnoughData):
            SSLv3Record().decode(data)
        #
        assert binascii.hexlify(data) == b"1603000088"


class TestConnectionClient(object):
    def _client_hello_01(self, record):
        assert isinstance(record, Handshake)

        assert record.type == 1

        assert record.length == 132

        assert record.payload.version.major == 3
        assert record.payload.version.minor == 0

        assert len(record.payload.random) == 32

        assert len(record.payload.session_id) == 0

        assert len(record.payload.cipher_suites) == 46

        assert len(record.payload.compression_methods) == 2

    def _client_key_exchange_01(self, record):
        assert record.type == 16

        assert record.length == 130

    def test_single(self):
        conn = SSLv30Connection(
            protocol_version=flextls.registry.version.SSLv3
        )
        assert conn.is_empty()

        conn.decode(
            prepare_handshake_data(
                client_hello_01
            )
        )
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._client_hello_01(record)

        conn.decode(
            prepare_handshake_data(
                client_key_exchange_01
            )
        )
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._client_key_exchange_01(record)

    def test_split(self):
        conn = SSLv30Connection(
            protocol_version=flextls.registry.version.SSLv3
        )
        assert conn.is_empty()

        for part in prepare_handshake_data_split(client_hello_01, 50):
            conn.decode(part)
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._client_hello_01(record)

        for part in prepare_handshake_data_split(client_key_exchange_01, 50):
            conn.decode(part)
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._client_key_exchange_01(record)


class TestConnectionServer(object):
    def _change_cipher_spec(self, record):
        assert record.type == 1

    def _connection_state(self, conn):
        assert conn.state.cipher_suite == 0x0039
        assert conn.state.client_random is None
        assert conn.state.server_random == binascii.unhexlify(server_hello_01_randmon)

    def _server_certificate_01(self, record):
        assert record.type == 11

        assert record.length == 841

        assert len(record.payload.certificate_list) == 1

        assert len(record.payload.certificate_list[0].value) == 835

    def _server_hello_01(self, record):
        assert record.type == 2

        assert record.length == 77

        assert record.payload.version.major == 3
        assert record.payload.version.minor == 0

        assert len(record.payload.random) == 32

        assert len(record.payload.session_id) == 32

        assert record.payload.cipher_suite == 0x0039

        assert record.payload.compression_method == 0

        assert len(record.payload.extensions) == 1

        ext = record.payload.extensions[0]
        assert ext.type == 0xff01

        ext = record.payload.extensions[0]
        assert ext.length == 1

    def _server_hello_done_01(self, record):
        assert record.type == 14

        assert record.length == 0

    def _server_key_exchange_01(self, record):
        assert record.type == 12

        assert record.length == 393

    def test_single(self):
        conn = SSLv30Connection(
            protocol_version=flextls.registry.version.SSLv3
        )
        assert conn.is_empty()

        conn.decode(
            prepare_handshake_data(
                server_hello_01
            )
        )
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_hello_01(record)

        conn.decode(
            prepare_handshake_data(
                server_certificate_01
            )
        )
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_certificate_01(record)

        conn.decode(
            prepare_handshake_data(
                server_key_exchange_01
            )
        )
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_key_exchange_01(record)

        conn.decode(
            prepare_handshake_data(
                server_hello_done_01
            )
        )
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_hello_done_01(record)

        self._connection_state(conn)

        # Change Cipher Spec, SSLv3.0, Length 1
        data = b"1403000001"
        # Change Cipher Spec Message
        data += b"01"
        conn.decode(
            binascii.unhexlify(data)
        )
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._change_cipher_spec(record)

    def test_single_multi(self):
        conn = SSLv30Connection(
            protocol_version=flextls.registry.version.SSLv3
        )
        assert conn.is_empty()

        data = server_hello_01
        data += server_certificate_01
        data += server_key_exchange_01
        data += server_hello_done_01
        conn.decode(
            prepare_handshake_data(
                data
            )
        )
        assert not conn.is_empty()
        record = conn.pop_record()
        self._server_hello_01(record)

        assert not conn.is_empty()
        record = conn.pop_record()
        self._server_certificate_01(record)

        assert not conn.is_empty()
        record = conn.pop_record()
        self._server_key_exchange_01(record)

        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_hello_done_01(record)

    def test_split(self):
        conn = SSLv30Connection(
            protocol_version=flextls.registry.version.SSLv3
        )
        assert conn.is_empty()

        for part in prepare_handshake_data_split(server_hello_01, 50):
            assert conn.is_empty()
            conn.decode(part)
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_hello_01(record)

        for part in prepare_handshake_data_split(server_certificate_01, 50):
            assert conn.is_empty()
            conn.decode(part)
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_certificate_01(record)

        conn.decode(
            prepare_handshake_data(
                server_key_exchange_01
            )
        )
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_key_exchange_01(record)

        for part in prepare_handshake_data_split(server_hello_done_01, 50):
            assert conn.is_empty()
            conn.decode(part)
        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_hello_done_01(record)

    def test_split_multi(self):
        conn = SSLv30Connection(
            protocol_version=flextls.registry.version.SSLv3
        )
        assert conn.is_empty()

        data = server_hello_01
        data += server_certificate_01
        data += server_key_exchange_01
        data += server_hello_done_01

        for part in prepare_handshake_data_split(data, 50):
            conn.decode(part)
        assert not conn.is_empty()
        record = conn.pop_record()
        self._server_hello_01(record)

        assert not conn.is_empty()
        record = conn.pop_record()
        self._server_certificate_01(record)

        assert not conn.is_empty()
        record = conn.pop_record()
        self._server_key_exchange_01(record)

        assert not conn.is_empty()
        record = conn.pop_record()
        assert conn.is_empty()
        self._server_hello_done_01(record)