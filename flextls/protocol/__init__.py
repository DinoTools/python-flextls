"""
The SSL/TLS Protocol
"""


class Protocol(object):
    payload_list = None

    def __init__(self, connection_state=None):
        self.fields = []
        self._connection_state = connection_state
        self.payload = None
        self.payload_identifier_field = None
        self.payload_length_field = None

    def __add__(self, payload):
        self.set_payload(payload)
        return self

    def __getattr__(self, name):
        return self.get_field_value(name)

    def __setattr__(self, name, value):
        if name == "fields":
            object.__setattr__(self, name, value)
            return

        for field in self.fields:
            if field.name == name:
                field.value = value
                #print("set")
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
        if isinstance(self.payload, Protocol):
            payload = self.payload.encode()
            if self.payload_identifier_field is not None:
                for pay_pattern, pay_class in self.payload_list.items():
                    if isinstance(payload, pay_class):
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
#            print(self)
#            print(field)
#            print(field.name)
            data = data + field.assemble()

        data = data + payload
        return data

    @classmethod
    def decode(cls, data, connection_state=None):
        obj = cls(
            connection_state=connection_state
        )
        data = obj.dissect(data)
        return (obj, data)

    def dissect(self, data, connection_state=None):
        if connection_state is not None:
            self._connection_state = connection_state
        # print(">>>")
        # print(self)
        # print(data)
        for field in self.fields:
            data = field.dissect(data)

        # print(self.payload_identifier_field)
        # print(self.payload_length_field)
        if self.payload_identifier_field is not None:
            if self.payload_length_field is None:
                payload_data = data
                data = data[:0]
            else:
                payload_length = self.get_field_value(self.payload_length_field)
                payload_data = data[:payload_length]
                data = data[payload_length:]

            #print(payload_length)
            payload_class = None
            if self.payload_list is not None:
                payload_class = self.payload_list.get(
                    self.get_field_value(self.payload_identifier_field),
                    None
                )
            if payload_class is None:
                self.payload = payload_data
            else:
                (obj, payload_data) = payload_class.decode(
                    payload_data,
                    connection_state=self._connection_state
                )
                self.payload = obj

        return data

    def encode(self):
        return self.assemble()

    def get_field(self, name):
        for field in self.fields:
            if field.name == name:
                return field
        return None

    def get_field_value(self, name):
        for field in self.fields:
            if field.name == name:
                return field.value

    def set_field_value(self, name, value):
        for field in self.fields:
            if field.name == name:
                field.value = value

    def set_payload(self, payload):
        if self.payload_identifier_field is not None:
            for pay_pattern, pay_class in self.payload_list.items():
                if isinstance(payload, pay_class):
                    self.set_field_value(
                        self.payload_identifier_field,
                        pay_pattern
                    )
                    break
        self.payload = payload
