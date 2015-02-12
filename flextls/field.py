import struct

import six

from flextls.exception import NotEnoughData


class Field(object):
    def __init__(self, name, default, fmt="H"):
        self._value = None
        self.set_value(default)
        self.name = name
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt
        self.size = struct.calcsize(self.fmt)

    def assemble(self):
        return struct.pack(self.fmt, self.value)

    def dissect(self, data):
        if len(data) < self.size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        self.value = struct.unpack(self.fmt, data[:self.size])[0]
        return data[self.size:]

    def get_value(self):
        return self._value

    def set_value(self, value):
        self._value = value

    value = property(get_value, set_value)

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


class UInt48Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "HI")

    def assemble(self):
        value = (int(self.value / (2**32)), int(self.value % (2**32)))
        return struct.pack(self.fmt, *value)

    def dissect(self, data):
        if len(data) < self.size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        tmp = struct.unpack(self.fmt, data[:self.size])
        self.value = (tmp[0] * (2 ** 32)) + tmp[1]
        return data[self.size:]

## Enums


class EnumField(Field):
    def __init__(self, name, default, enums, fmt="H"):
        self.enums = enums
        Field.__init__(self, name, default, fmt)

    def get_value_name(self):
        return "%s (%x)" % (
            self.enums.get(self._value, 'n/a'),
            self._value
        )

    def set_value(self, value, force=False):
        if force:
            self._value = value
            return

        if value is None:
            self._value = value
            return

        if isinstance(value, six.integer_types):
            self._value = value
            return

        if isinstance(value, six.string_types):
            for v, n in self.enums.items():
                if n == value:
                    self._value = v
                    return
            raise ValueError("Unable to find value name in enum list")

        raise TypeError(
            "Value for '%s' must by of type String or Integer not '%s'" % (
                self.name,
                type(value)
            )
        )

    value = property(Field.get_value, set_value)


class UByteEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "B")


class UShortEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "H")


## Vectors


class VectorListBaseField(object):
    def __init__(self, name, item_class=None, item_class_args=None, fmt="H"):
        self.name = name
        self.item_class = item_class
        if item_class_args is None:
            item_class_args = []
        self.item_class_args = item_class_args
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
        payload_size = struct.unpack(self.fmt, data[:len_size])[0]
        data = data[len_size:]

        if len(data) < payload_size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        payload_data = data[:payload_size]
        while len(payload_data) > 0:
            item = self.item_class(*self.item_class_args)
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
    def __init__(self, name, item_class=None, item_class_args=None):
        VectorListBaseField.__init__(self, name, item_class, item_class_args, fmt="B")


class VectorListUShortField(VectorListBaseField):
    def __init__(self, name, item_class=None, item_class_args=None):
        VectorListBaseField.__init__(self, name, item_class, item_class_args, fmt="H")


class VectorListInteger3Field(VectorListBaseField):
    def __init__(self, name, item_class=None, item_class_args=None):
        VectorListBaseField.__init__(self, name, item_class, item_class_args, fmt="BH")

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


class ServerNameListField(VectorListUShortField):
    def __init__(self, name):
        VectorListUShortField.__init__(
            self,
            name,
            ServerNameField,
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
    def __init__(self, name, default=b"", fmt="H", connection_state=None):
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
    payload_list = None

    def __init__(self, name, fields=[]):
        self.fields = []
        self.name = name
        self.fields = fields
        self.payload_identifier_field = None
        self.payload_length_field = None

    def __getattr__(self, name):
        return self.get_field_value(name)

    def __setattr__(self, name, value):
        if name == "fields":
            object.__setattr__(self, name, value)
            return

        for field in self.fields:
            if field.name == name:
                field.value = value
                return

        object.__setattr__(self, name, value)

    @classmethod
    def add_payload_type(cls, pattern, payload_class):
        if cls.payload_list is None:
            cls.payload_list = {}
        cls.payload_list[pattern] = payload_class

    def assemble(self):
        data = b""
        payload = b""
        if not isinstance(self.payload, bytes) and self.payload is not None:
            payload = self.payload.assemble()
            if self.payload_identifier_field is not None:
                for pay_pattern, pay_class in self.payload_list.items():
                    if isinstance(self.payload, pay_class):
                        self.set_field_value(
                            self.payload_identifier_field,
                            pay_pattern
                        )
                        break
        elif self.payload is not None:
            payload = self.payload

        if self.payload_length_field is not None and payload is not None:
            self.set_field_value(
                self.payload_length_field,
                len(payload)
            )

        for field in self.fields:
            data = data + field.assemble()

        data = data + payload
        return data

    def dissect(self, data):
        for field in self.fields:
            data = field.dissect(data)

        if self.payload_identifier_field is not None:
            if self.payload_length_field is None:
                payload_data = data
                data = data[:0]
            else:
                payload_length = self.get_field_value(self.payload_length_field)
                payload_data = data[:payload_length]
                data = data[payload_length:]

            payload_class = None
            if self.payload_list is not None:
                payload_class = self.payload_list.get(
                    self.get_field_value(self.payload_identifier_field),
                    None
                )
            if payload_class is None:
                self.payload = payload_data
            else:
                obj = payload_class("onknown")
                payload_data = obj.dissect(payload_data)
                self.payload = obj

        return data

    def get_field_value(self, name):
        for field in self.fields:
            if field.name == name:
                return field.value

    def set_field_value(self, name, value):
        for field in self.fields:
            if field.name == name:
                field.value = value

    @property
    def value(self):
        return self


class ServerNameField(MultiPartField):
    def __init__(self, name="test", **kwargs):
        MultiPartField.__init__(self, name, **kwargs)
        self.fields = [
            UByteEnumField(
                "name_type",
                None,
                {
                    0: "host_name",
                    255: None
                }
            ),
        ]
        self.payload_identifier_field = "name_type"


class HostNameField(VectorUShortField):
    pass


ServerNameField.add_payload_type(0, HostNameField)


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
