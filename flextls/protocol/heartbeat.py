from flextls.field import UInt8EnumField, UInt16Field
from flextls.protocol import Protocol


class Heartbeat(Protocol):
    """
    Handle Heartbeat Request and Response Messages

    * RFC6520
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UInt8EnumField(
                "type",
                None,
                {
                    1: "request",
                    2: "response",
                    255: None
                }
            ),
            UInt16Field("payload_length", 0)
        ]
        self.padding = b""
        self.payload_length_field = "payload_length"
        self.payload_identifier_field = False

    def assemble(self):
        data = Protocol.assemble(self)
        data = data + self.padding
        return data

    def dissect(self, data, payload_auto_decode=True):
        data = Protocol.dissect(
            self,
            data,
            payload_auto_decode=payload_auto_decode
        )
        self.padding = data
        return b""
