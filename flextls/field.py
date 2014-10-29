import struct

from flextls.exception import NotEnoughData


class Field(object):
    def __init__(self, name, default, fmt="H"):
        self.value = default
        self.name = name
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt
        self.size = struct.calcsize(self.fmt)

    def assemble(self):
#        print("---")
#        print(self)
#        print(self.fmt)
#        print(self.value)
        return struct.pack(self.fmt, self.value)

    def dissect(self, data):
        if len(data) < self.size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        self.value = struct.unpack(self.fmt, data[:self.size])[0]
        return data[self.size:]


## Numbers


class UByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

class UShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "H")


class UInteger3Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "BH")

    def assemble(self):
        value = (int(self.value / (2**16)), int(self.value % (2**16)))
        return struct.pack(self.fmt, *value)

    def dissect(self, data):
        if len(data) < self.size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        tmp = struct.unpack(self.fmt, data[:self.size])
        self.value = (tmp[0] * (2 ** 16)) + tmp[1]
        return data[self.size:]


## Enums


class EnumField(Field):
    def __init__(self, name, default, enum, fmt="H"):
        self.enum = enum
        Field.__init__(self, name, default, fmt)

class UByteEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "B")


class UShortEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "H")


## Vectors


class VectorListBaseField(object):
    def __init__(self, name, item_class=None, fmt="H"):
        self.name = name
        self.item_class = item_class
        self.items = []
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt

    def assemble(self):
        data = b""
        for item in self.items:
            data = data + item.assemble()
        return struct.pack(self.fmt, len(data)) + data

    def dissect(self, data):
        len_size = struct.calcsize(self.fmt)

        if len(data) < len_size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )
#        print(self.name)
#        print(len_size)
#        print(data)
        payload_size = struct.unpack(self.fmt, data[:len_size])[0]
#        print(payload_size)
        data = data[len_size:]

        if len(data) < payload_size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        payload_data = data[:payload_size]
        while len(payload_data) > 0:
            item = self.item_class()
            payload_data = item.dissect(payload_data)
            self.items.append(item)

        return data[payload_size:]

    @property
    def size(self):
        size = struct.calcsize(self.fmt)
        for item in self.items:
            size = size + item.size
        return size

    @property
    def value(self):
        return self.items


class VectorListUByteField(VectorListBaseField):
    def __init__(self, name, item_class=None):
        VectorListBaseField.__init__(self, name, item_class, fmt="B")


class VectorListUShortField(VectorListBaseField):
    def __init__(self, name, item_class=None):
        VectorListBaseField.__init__(self, name, item_class, fmt="H")


class VectorListInteger3Field(VectorListBaseField):
    def __init__(self, name, item_class=None):
        VectorListBaseField.__init__(self, name, item_class, fmt="BH")

    def assemble(self):
        data = b""
        for item in self.items:
            data = data + item.assemble()

        value = (int(self.value / (2**16)), int(self.value % (2**16)))
        return struct.pack(self.fmt, *value) + data

    def dissect(self, data):
        if len(data) < self.size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        tmp = struct.unpack(self.fmt, data[:self.size])
        payload_length = (tmp[0] * (2 ** 16)) + tmp[1]
        data = data[self.size:]


        if len(data) < payload_length:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        payload_data = data[:payload_length]
        while len(payload_data) > 0:
            item = self.item_class()
            payload_data = item.dissect(payload_data)
            self.items.append(item)

        return data[payload_length:]


class CertificateListField(VectorListInteger3Field):
    def __init__(self, name):
        VectorListInteger3Field.__init__(
            self,
            name,
            CertificateField,
        )


class CipherSuitesField(VectorListUShortField):
    def __init__(self, name):
        VectorListUShortField.__init__(
            self,
            name,
            CipherSuiteField,
        )


class ExtensionsField(VectorListUShortField):
    def __init__(self, name):
        from flextls.protocol.handshake.extension import Extension
        VectorListUShortField.__init__(
            self,
            name,
            Extension
        )

    def assemble(self):
        if len(self.items) == 0:
            return b""
        return VectorListUShortField.assemble(self)

    def dissect(self, data):
        if len(data) == 0:
            return data
        return VectorListUShortField.dissect(self, data)


class CompressionMethodsField(VectorListUByteField):
    def __init__(self, name):
        VectorListUByteField.__init__(
            self,
            name,
            CompressionMethodField,
        )


class VectorBaseField(object):
    def __init__(self, name, default=b"", fmt="H"):
        self.name = name
        self.value = default
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt

    def assemble(self):
        data = self.value
        if data is None:
            data = b""
        return struct.pack(self.fmt, len(data)) + data

    def dissect(self, data):
        len_size = struct.calcsize(self.fmt)

        if len(data) < len_size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        value_size = struct.unpack(self.fmt, data[:len_size])[0]
        data = data[len_size:]
        self.value = data[:value_size]
        return data[value_size:]

    @property
    def size(self):
        size = struct.calcsize(self.fmt)
        if self.value is not None:
            size = size + len(self.value)
        return size


class VectorUShortField(VectorBaseField):
    def __init__(self, name):
        VectorBaseField.__init__(self, name, fmt="H")


class VectorUByteField(VectorBaseField):
    def __init__(self, name):
        VectorBaseField.__init__(self, name, fmt="B")


class VectorInteger3Field(VectorBaseField):
    def __init__(self, name):
        VectorBaseField.__init__(self, name, fmt="BH")

    def assemble(self):
        data_length = len(self.value)
        len_value = (int(data_length / (2**16)), int(data_length % (2**16)))
        return struct.pack(self.fmt, *len_value) + self.value

    def dissect(self, data):
        if len(data) < self.size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        tmp = struct.unpack(self.fmt, data[:self.size])
        data_length = (tmp[0] * (2 ** 16)) + tmp[1]
        data = data[self.size:]

        if len(data) < data_length:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        self.value = data[:data_length]
        return data[data_length:]


class CertificateField(VectorInteger3Field):
    def __init__(self, name="certificate"):
        VectorInteger3Field.__init__(self, name)


## Multipart


class MultiPartField(object):
    def __init__(self, name, fields):
        self.fields = []
        self.name = name
        self.fields = fields

    def __getattr__(self, name):
        for field in self.fields:
            if field.name == name:
                return field.value
        raise AttributeError

    def __setattr__(self, name, value):
        if name == "fields":
            object.__setattr__(self, name, value)
            return

        for field in self.fields:
            if field.name == name:
                field.value = value
                return

        object.__setattr__(self, name, value)

    def assemble(self):
        data = b""
        for field in self.fields:
#            print(field)
            data = data + field.assemble()
        return data

    def dissect(self, data):
        for field in self.fields:
            data = field.dissect(data)
        return data

    def get_field_value(self, name):
        for field in self.fields:
            if field.name == name:
                return field.value

    @property
    def value(self):
        return self


class VersionField(MultiPartField):
    def __init__(self, name):
        MultiPartField.__init__(
            self,
            name,
            [
                UByteField("major", 3),
                UByteField("minor", 0)
            ]
        )


class RandomField(MultiPartField):
    def __init__(self, name):
        MultiPartField.__init__(
            self,
            name,
            [
                # ToDo: extract time stamp
                Field("random_bytes", 0, fmt="32s")
            ]
        )


class SignatureAndHashAlgorithmField(MultiPartField):
    def __init__(self, name):
        MultiPartField.__init__(
            self,
            name,
            [
                UByteField("hash", 0),
                UByteField("signature", 0)
            ]
        )


## Custom

class CipherSuiteField(UShortField):
    def __init__(self, name="unnamed"):
        UShortField.__init__(self, name, None)


class SSLv2CipherSuiteField(UInteger3Field):
    def __init__(self, name="unnamed"):
        UInteger3Field.__init__(self, name, None)


class CompressionMethodField(UByteField):
    def __init__(self, name="unnamed"):
        UByteField.__init__(self, name, None)
