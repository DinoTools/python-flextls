import struct

import six

from flextls.exception import NotEnoughData


class Field(object):
    """
    Base class for all fields. Used to extract additional information.

    :param String name: Name of the field
    :param Mixed default: Default field value
    :param String fmt: Format string used to decode the data
    """
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
        """
        Assemble the field by using the given value.

        :return: The assembled data
        :rtype: bytes
        """
        return struct.pack(self.fmt, self.value)

    def dissect(self, data):
        """
        Dissect the field.

        :param bytes data: The data to extract the field value from
        :return: The rest of the data not used to dissect the field value
        :rtype: bytes
        """
        if len(data) < self.size:
            raise NotEnoughData(
                "Not enough data to decode field '%s' value" % self.name
            )

        self.value = struct.unpack(self.fmt, data[:self.size])[0]
        return data[self.size:]

    def get_value(self):
        """
        Return the field value.

        :return: The value of the field
        :rtype: Mixed
        """
        return self._value

    def set_value(self, value):
        """
        Set the value of the field

        :param Mixed value: The value
        """
        self._value = value

    value = property(get_value, set_value)

# Numbers


class UInt8Field(Field):
    """
    Field representing an 8-bit unsigned integer value(range: 0 through 255 decimal).
    """
    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")


class UInt16Field(Field):
    """
    Field representing an 16-bit unsigned integer value(range: 0 through 65535 decimal).
    """
    def __init__(self, name, default):
        Field.__init__(self, name, default, "H")


class UInt24Field(Field):
    """
    Field representing an 16-bit unsigned integer value.
    """
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
    """
    Field representing an 48-bit unsigned integer value.
    """
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


class RandomField(Field):
    """
    Random data.
    """
    def __init__(self, name):
        Field.__init__(self, name, default=b"A"*32, fmt="32s")


# Enums


class EnumField(Field):
    """
    The field should only use the defined values.

    :param String name: The name of the field
    :param Mixed default: A value defined in the enums list
    :param Dict enums: List of possible values.
    :param String fmt: The format string
    """
    def __init__(self, name, default, enums, fmt="H"):
        self.enums = enums
        Field.__init__(self, name, default, fmt)

    def get_value_name(self, pretty=False):
        """
        Get the name of the value

        :param Boolean pretty: Return the name in a pretty format
        :return: The name
        :rtype: String
        """
        if pretty:
            return "%s (%x)" % (
                self.enums.get(self._value, "n/a"),
                self._value
            )

        return self.enums.get(self._value, "n/a")

    def set_value(self, value, force=False):
        """
        Set the value.

        :param String|Integer value: The value to set. Must be in the enum list.
        :param Boolean force: Set the value without checking it

        :raises ValueError: If value name given but it isn't available
        :raises TypeError: If value is not String or Integer
        """
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


class UInt8EnumField(EnumField):
    """
    The field should only use the defined values. The value must be an 8-Bit unsigned integer.

    :param String name: The name of the field
    :param Mixed default: A value defined in the enums list
    :param Dict enums: List of possible values.
    """
    def __init__(self, name, default, enums):
        EnumField.__init__(self, name, default, enums, "B")


class UInt16EnumField(EnumField):
    """
    The field should only use the defined values. The value must be an 16-Bit unsigned integer.

    :param String name: The name of the field
    :param Mixed default: A value defined in the enums list
    :param Dict enums: List of possible values.
    """
    def __init__(self, name, default, enums):
        EnumField.__init__(self, name, default, enums, "H")


# Vectors


class VectorListBaseField(object):
    """
    A vector as defined by the RFC is a single dimensioned array.

    :param String name: The name of the field
    :param flextls.field.Field item_class:
    :param List item_class_args:
    :param String fmt: The format string
    """
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


class VectorListUInt8Field(VectorListBaseField):
    """
    A vector as defined by the RFC is a single dimensioned array.
    The length identifier of this vector is a 8-bit unsigned integer.

    :param String name: The name of the field
    :param flextls.field.Field item_class:
    :param List item_class_args:
    :param String fmt: The format string of the length identifier
    """
    def __init__(self, name, item_class=None, item_class_args=None):
        VectorListBaseField.__init__(self, name, item_class, item_class_args, fmt="B")


class VectorListUInt16Field(VectorListBaseField):
    """
    A vector as defined by the RFC is a single dimensioned array.
    The length identifier of this vector is a 16-bit unsigned integer.

    :param String name: The name of the field
    :param flextls.field.Field item_class:
    :param List item_class_args:
    :param String fmt: The format string of the length identifier
    """
    def __init__(self, name, item_class=None, item_class_args=None):
        VectorListBaseField.__init__(self, name, item_class, item_class_args, fmt="H")


class VectorListInt24Field(VectorListBaseField):
    """
    A vector as defined by the RFC is a single dimensioned array.
    The length identifier of this vector is a 24-bit unsigned integer.

    :param String name: The name of the field
    :param flextls.field.Field item_class:
    :param List item_class_args:
    :param String fmt: The format string of the length identifier
    """
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


class CertificateListField(VectorListInt24Field):
    """
    List of certificates

    :param String name: The name of the field
    """
    def __init__(self, name):
        VectorListInt24Field.__init__(
            self,
            name,
            CertificateField,
        )


class CipherSuitesField(VectorListUInt16Field):
    """
    List of cipher suites.

    :param String name: The name of the field
    """
    def __init__(self, name):
        VectorListUInt16Field.__init__(
            self,
            name,
            CipherSuiteField,
        )


class ServerNameListField(VectorListUInt16Field):
    """
    List of server names

    :param String name: The name of the field
    """
    def __init__(self, name):
        VectorListUInt16Field.__init__(
            self,
            name,
            ServerNameField,
        )


class ExtensionsField(VectorListUInt16Field):
    """
    List of extensions

    :param String name: The name of the field
    """
    def __init__(self, name):
        from flextls.protocol.handshake.extension import Extension
        VectorListUInt16Field.__init__(
            self,
            name,
            Extension
        )

    def assemble(self):
        if len(self.items) == 0:
            return b""
        return VectorListUInt16Field.assemble(self)

    def dissect(self, data):
        if len(data) == 0:
            return data
        return VectorListUInt16Field.dissect(self, data)


class CompressionMethodsField(VectorListUInt8Field):
    """
    List of compression methods

    :param String name: The name of the field
    """
    def __init__(self, name):
        VectorListUInt8Field.__init__(
            self,
            name,
            CompressionMethodField,
        )


class VectorBaseField(object):
    """
    A vector as defined by the RFC is a single dimensioned array.

    :param String name: The name of the field
    :param Bytes default: Default value of the field
    :param String fmt: The format string of the length identifier
    """
    def __init__(self, name, default=b"", fmt="H", connection=None):
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


class VectorUInt8Field(VectorBaseField):
    """
    A vector as defined by the RFC is a single dimensioned array.
    The length identifier of this vector is a 8-bit unsigned integer.

    :param String name: The name of the field
    :param String fmt: The format string of the length identifier
    """
    def __init__(self, name):
        VectorBaseField.__init__(self, name, fmt="B")


class VectorUInt16Field(VectorBaseField):
    """
    A vector as defined by the RFC is a single dimensioned array.
    The length identifier of this vector is a 16-bit unsigned integer.

    :param String name: The name of the field
    :param String fmt: The format string of the length identifier
    """
    def __init__(self, name):
        VectorBaseField.__init__(self, name, fmt="H")


class VectorInt24Field(VectorBaseField):
    """
    A vector as defined by the RFC is a single dimensioned array.
    The length identifier of this vector is a 24-bit unsigned integer.

    :param String name: The name of the field
    :param String fmt: The format string of the length identifier
    """
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


class CertificateField(VectorInt24Field):
    """
    A certificate.

    :param String name: The name of the field
    """
    def __init__(self, name="certificate"):
        VectorInt24Field.__init__(self, name)


class HostNameField(VectorUInt16Field):
    """
    The hostname.
    """
    pass

# Multipart


class MultiPartField(object):
    """
    A field consisting of more than one value.

    :param String name: The name of the field
    :param fields: List of sub fields
    """
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
    """
    The server name
    """
    def __init__(self, name="test", **kwargs):
        MultiPartField.__init__(self, name, **kwargs)
        self.fields = [
            UInt8EnumField(
                "name_type",
                None,
                {
                    0: "host_name",
                    255: None
                }
            ),
        ]
        self.payload_identifier_field = "name_type"


ServerNameField.add_payload_type(0, HostNameField)


class VersionField(MultiPartField):
    """
    The protocol version field.

    :param String name: Name of the field
    """
    def __init__(self, name):
        MultiPartField.__init__(
            self,
            name,
            [
                UInt8Field("major", 3),
                UInt8Field("minor", 0)
            ]
        )


class SignatureAndHashAlgorithmField(MultiPartField):
    """
    Representing a signature and hash algorithm
    """
    def __init__(self, name):
        MultiPartField.__init__(
            self,
            name,
            [
                UInt8Field("hash", 0),
                UInt8Field("signature", 0)
            ]
        )


class ServerDHParamsField(MultiPartField):
    """
    RFC5246 Section 7.4.3. Server Key Exchange Message
    """
    def __init__(self, name):
        MultiPartField.__init__(
            self,
            name,
            [
                VectorUInt16Field("dh_p"),
                VectorUInt16Field("dh_g"),
                VectorUInt16Field("dh_Ys")
            ]
        )

# Custom

class CipherSuiteField(UInt16Field):
    """
    A cipher suite
    """
    def __init__(self, name="unnamed"):
        UInt16Field.__init__(self, name, None)


class SSLv2CipherSuiteField(UInt24Field):
    """
    A cipher suite for SSLv2
    """
    def __init__(self, name="unnamed"):
        UInt24Field.__init__(self, name, None)


class CompressionMethodField(UInt8Field):
    """
    Compression method
    """
    def __init__(self, name="unnamed"):
        UInt8Field.__init__(self, name, None)
