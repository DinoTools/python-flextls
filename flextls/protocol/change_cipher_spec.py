from flextls.field import UByteEnumField
from flextls.protocol import Protocol


class ChangeCipherSpec(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UByteEnumField(
                "type",
                None,
                {
                    1: "change_cipher_spec",
                    255: None
                }
            ),
        ]