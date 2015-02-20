from flextls.field import UInt8EnumField
from flextls.protocol import Protocol


class ChangeCipherSpec(Protocol):
    """
    Handle Change Cipher Spec Protocol
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UInt8EnumField(
                "type",
                None,
                {
                    1: "change_cipher_spec",
                    255: None
                }
            ),
        ]