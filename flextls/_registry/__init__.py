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
        self.register(
            "tls.signature_algorithms",
            TLSSignatureAlgorithmRegistry()
        )
        self.register(
            "sslv2.cipher_suites",
            SSLv2CipherSuiteRegistry()
        )
        self.register(
            "ec.named_curves",
            ECNamedCurveRegistry()
        )
        self.register("version.SSLv2", 2)
        self.register("version.SSLv3", 4)
        self.register("version.TLSv10", 8)
        self.register("version.TLSv11", 16)
        self.register("version.TLSv12", 32)


class BaseRegistry(object):
    def __init__(self):
        self._values = []
        self._arg_names = [
            "id",
            "name",
            "dtls",
            "references",
        ]
        self._item_cls = None

    def __iter__(self):
        return self._values.__iter__()

    def append(self, value):
        if self.get(value.id) is not None:
            return
        self._values.append(value)

    def clear(self):
        self._values = []

    def get(self, id):
        for value in self._values:
            if value.id == id:
                return value

        # ToDo: return unknown?
        return None

    def get_dict(self):
        result = {}
        for item in self._values:
            result[item.id] = item
        return result

    def get_ids(self):
        result = []
        for item in self._values:
            result.append(item.id)
        return result

    def load(self, values, replace=False):
        if replace is True:
            self.clear()

        for args in values:
            self.append(
                CipherSuite(**args)
            )

    def load_list(self, values, replace=False):
        if replace is True:
            self.clear()

        for row_values in values:
            args = {}
            for i, name in enumerate(self._arg_names):
                if len(row_values) <= i:
                    continue
                args[name] = row_values[i]

            self.append(
                self._item_cls(**args)
            )


class BaseCipherSuiteRegistry(BaseRegistry):
    def __init__(self):
        BaseRegistry.__init__(self)
        self._arg_names = [
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
        self._item_cls = CipherSuite


class SSLv2CipherSuiteRegistry(BaseCipherSuiteRegistry):
    def __init__(self, auto_load=True):
        BaseCipherSuiteRegistry.__init__(self)
        if auto_load:
            from flextls._registry.data import ssl_cipher_suites
            self.load(ssl_cipher_suites, replace=True)


class TLSCipherSuiteRegistry(BaseCipherSuiteRegistry):
    def __init__(self, auto_load=True):
        BaseCipherSuiteRegistry.__init__(self)
        if auto_load:
            from flextls._registry.data import tls_cipher_suites
            self.load(tls_cipher_suites, replace=True)


class TLSSignatureAlgorithmRegistry(BaseRegistry):
    def __init__(self, auto_load=True):
        BaseRegistry.__init__(self)
        self._item_cls = ECNamedCurve
        if auto_load:
            from flextls._registry.data import tls_signature_algorithms
            self.load(tls_signature_algorithms, replace=True)


class ECNamedCurveRegistry(BaseRegistry):
    def __init__(self, auto_load=True):
        BaseRegistry.__init__(self)
        self._item_cls = ECNamedCurve
        if auto_load:
            from flextls._registry.data import ec_named_curves
            self.load(ec_named_curves, replace=True)


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


class BaseRegistryItem(object):
    def __init__(self, id, name=None, dtls=None, references=None):
        self.id = id
        self.name = name
        self.dtls = dtls
        self.references = references


class TLSSignatureAlgorithm(BaseRegistryItem):
    def __init__(self, id, **kwargs):
        BaseRegistryItem.__init__(self, id, **kwargs)


class ECNamedCurve(BaseRegistryItem):
    def __init__(self, id, **kwargs):
        BaseRegistryItem.__init__(self, id, **kwargs)
