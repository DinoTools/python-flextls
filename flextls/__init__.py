from flextls._registry import Registry


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
