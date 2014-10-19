import binascii

from flextls.protocol.record import Record, RecordSSLv2


class TestClientHello(object):

    def _get_record(self):
        # Length: 46, Client Hello, SSL 2.0
        data = b"802e010002"
        # Cipher Spec Length 21, Session ID Length: 0, Challenge Length: 16
        data += b"001500000010"
        # Cipher Specs
        data += b"0500800300800100800700c0060040040080020080"
        # Challenge: 16
        data += b"44daa86b5ce6cbddde1d6948488e258e"

        (record, data) = Record().decode(binascii.unhexlify(data))
        return record

    def test_record_length(self):
        record = self._get_record()
        assert record.length == 46

    def test_record_padding(self):
        record = self._get_record()
        assert len(record.padding) == 0

    def test_record_content_type(self):
        record = self._get_record()
        assert record.type == 1

    def test_client_hello_version(self):
        record = self._get_record()
        assert record.payload.version.major == 0
        assert record.payload.version.minor == 2

    def test_client_hello_session_id(self):
        record = self._get_record()
        assert record.payload.session_id_length == 0
        assert len(record.payload.session_id) == 0

    def test_client_hello_cipher_suites(self):
        record = self._get_record()
        assert record.payload.cipher_suites_length == 21
        assert len(record.payload.cipher_suites) == 7

    def test_client_hello_chalenge(self):
        record = self._get_record()
        assert record.payload.challenge_length == 16
        assert len(record.payload.challenge) == 16


class TestServerHello(object):

    def _get_record(self):
        # Length: 883, Server Hello
        data = b"837304"
        # Session ID Hit: False, Certificate Type, Version SSL 2.0
        data += b"00010002"
        # Certificate Len: 835, Cipher Spec Len: 21, Connection ID Len: 16
        data += b"034300150010"
        # Certificate
        data += b"3082033f308202a8a00302010202024ae6300d06092a864886"
        data += b"f70d01010505003081bb310b3009060355040613022d2d3112"
        data += b"301006035504080c09536f6d6553746174653111300f060355"
        data += b"04070c08536f6d654369747931193017060355040a0c10536f"
        data += b"6d654f7267616e697a6174696f6e311f301d060355040b0c16"
        data += b"536f6d654f7267616e697a6174696f6e616c556e6974311e30"
        data += b"1c06035504030c156c6f63616c686f73742e6c6f63616c646f"
        data += b"6d61696e3129302706092a864886f70d010901161a726f6f74"
        data += b"406c6f63616c686f73742e6c6f63616c646f6d61696e301e17"
        data += b"0d3134303530343035343935345a170d313530353034303534"
        data += b"3935345a3081bb310b3009060355040613022d2d3112301006"
        data += b"035504080c09536f6d6553746174653111300f06035504070c"
        data += b"08536f6d654369747931193017060355040a0c10536f6d654f"
        data += b"7267616e697a6174696f6e311f301d060355040b0c16536f6d"
        data += b"654f7267616e697a6174696f6e616c556e6974311e301c0603"
        data += b"5504030c156c6f63616c686f73742e6c6f63616c646f6d6169"
        data += b"6e3129302706092a864886f70d010901161a726f6f74406c6f"
        data += b"63616c686f73742e6c6f63616c646f6d61696e30819f300d06"
        data += b"092a864886f70d010101050003818d0030818902818100b712"
        data += b"157298a96c4f64027fec7fc42f66f5d5d46da4096b5f0b8e77"
        data += b"9b5677dcecba2eb8bca41b11eda4ee5f19d86cbb714d0a38a3"
        data += b"4c0bc7b02ec3594c56b1b5aea33d3f2de966b3f7256594b990"
        data += b"fa7c0de34d99d9d8a0a626b49a0234822a17868316e25aa58f"
        data += b"ebd23693744a8bf0836fe5d337b6caebeaef0b583758340f4a"
        data += b"d10203010001a350304e301d0603551d0e041604149744e81b"
        data += b"a93cd6eec904f7da99100b1e6c37e429301f0603551d230418"
        data += b"301680149744e81ba93cd6eec904f7da99100b1e6c37e42930"
        data += b"0c0603551d13040530030101ff300d06092a864886f70d0101"
        data += b"0505000381810032e346b65873c17df9b86d61fb2692255a46"
        data += b"54861cf77ddc82feb03827f6074f9f2671033abc6d6f3d4cdc"
        data += b"41545bee1ff7e0d94d59d70e9f8150e63aee5f0ffe3c7b3cfd"
        data += b"053ac1991254284376b5063637fd8aee38c9b2ca1ec5c49c45"
        data += b"d27038474f393f2dc0233d72afa769085ffe7e4d46363525ce"
        data += b"04b9cb4d6e88b9595394"
        # Cipher Specs
        data += b"0500800300800100800700c0060040040080020080"
        # Connection ID
        data += b"091968f2228096a12b87ee83f96669c2"

        (record, data) = RecordSSLv2().decode(binascii.unhexlify(data))
        return record

    def test_record_length(self):
        record = self._get_record()
        assert record.length == 883

    def test_record_padding(self):
        record = self._get_record()
        assert len(record.padding) == 0

    def test_record_content_type(self):
        record = self._get_record()
        assert record.type == 4

    def test_server_hello_version(self):
        record = self._get_record()
        assert record.payload.version.major == 0
        assert record.payload.version.minor == 2

    def test_server_hello_connection_id(self):
        record = self._get_record()
        assert record.payload.connection_id_length == 16
        assert len(record.payload.connection_id) == 16

    def test_server_hello_cipher_suites(self):
        record = self._get_record()
        assert record.payload.cipher_suites_length == 21
        assert len(record.payload.cipher_suites) == 7

    def test_server_hello_certificate_type(self):
        record = self._get_record()
        assert record.payload.certificate_type == 1

    def test_server_hello_certificate(self):
        record = self._get_record()
        assert record.payload.certificate_length == 835
        assert len(record.payload.certificate) == 835
