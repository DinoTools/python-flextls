class RegistryNamespace(object):
    def __init__(self):
        self._values = {}
        self._namespaces = {}

    def __getattr__(self, name):
        if name in self._values:
            return self._values[name]

        if name in self._namespaces:
            return self._namespaces[name]

        return None

    def register(self, name, value):
        names = name.split(".", 1)
        if len(names) == 1:
            self._values[names[0]] = value
        elif len(names) == 2:
            if names[0] not in self._namespaces:
                self._namespaces[names[0]] = RegistryNamespace()
            self._namespaces[names[0]].register(names[1], value)
        else:
            # ToDo: error
            pass


class Registry(RegistryNamespace):
    def __init__(self):
        RegistryNamespace.__init__(self)
        self.register(
            "tls.cipher_suites",
            TLSCipherSuiteRegistry()
        )
        self.register("version.SSLv2", 2)
        self.register("version.SSLv3", 4)
        self.register("version.TLSv10", 8)
        self.register("version.TLSv11", 16)
        self.register("version.TLSv12", 32)


class TLSCipherSuiteRegistry(object):
    def __init__(self, auto_load=True):
        self._cipher_suites = []
        from flextls._registry.data import tls_cipher_suites
        self.load(tls_cipher_suites, replace=True)

    def __iter__(self):
        return self._cipher_suites.__iter__()

    def append(self, cipher_suite):
        if self.get(cipher_suite.id) is not None:
            return
        self._cipher_suites.append(cipher_suite)

    def clear(self):
        self._cipher_suites = []

    def get(self, id):
        for cipher_suite in self._cipher_suites:
            if cipher_suite.id == id:
                return cipher_suite

        # ToDo: return unknown?
        return None

    def get_dict(self):
        result = {}
        for item in self._cipher_suites:
            result[item.id] = item
        return result

    def get_ids(self):
        result = []
        for item in self._cipher_suites:
            result.append(item.id)
        return result


    def load(self, cipher_suites, replace=False):
        if replace == True:
            self.clear()

        for args in cipher_suites:
            self.append(
                CipherSuite(**args)
            )

    def load_list(self, cipher_suites, replace=False):
        if replace == True:
            self.clear()

        arg_names = [
            "id",
            "name",
            "protocol",
            "bits",
            "alg_bits",
            "key_exchagne",
            "authentication",
            "encryption",
            "mac",
            "dtls",
            "export"
        ]
        for values in cipher_suites:
            args = {}
            for i, name in enumerate(arg_names):
                if len(values) <= i:
                    continue
                args[name] = values[i]

            self.append(
                CipherSuite(**args)
            )


class CipherSuite(object):
    def __init__(self, id, protocol=None, name=None, bits=None, alg_bits=None,
                 key_exchange=None, authentication=None, encryption=None,
                 mac=None, dtls=None, references=None, export=None):
        self.id = id
        self.protocol = protocol
        self.name = name
        self.bits = bits
        self.alg_bits = alg_bits
        self.key_exchange = key_exchange
        self.authentication = authentication
        self.encryption = encryption
        self.mac = mac
        self.dtls = dtls
        self.references = references
        self.export = export
