"""

"""
from flextls.protocol import Protocol
from flextls.field import UInt8Field, UInt16Field, VectorListUInt8Field, VectorUInt16Field
from flextls.field import UInt8EnumField, UInt16EnumField, VectorListUInt16Field
from flextls.field import SignatureAndHashAlgorithmField
from flextls.field import ServerNameListField


class Extension(Protocol):
    """
    Handle TLS and DTLS Extensions
    """

    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UInt16EnumField(
                "type",
                None,
                {
                    13: "signature_algorithms",
                    65535: None
                }
            ),
            UInt16Field("length", 0),
        ]
        self.payload_identifier_field = "type"
        self.payload_length_field = "length"


class ServerNameIndication(Protocol):
    """
    Handle Server Name Indication extension

    * RFC6066 (Section 3)
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            ServerNameListField("server_name_list"),
        ]

    @classmethod
    def decode(cls, data, connection_state=None, payload_auto_decode=True):
        obj = cls(
            connection_state=connection_state
        )
        if len(data) > 0:
            data = obj.dissect(data)

        return (obj, data)

    def encode(self):
        if len(self.server_name_list) == 0:
            return b""
        else:
            return self.assemble()


Extension.add_payload_type(0x0000, ServerNameIndication)


class Heartbeat(Protocol):
    """
    Handle Heartbeat extension
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UInt8EnumField(
                "mode",
                None,
                {
                    1: "peer_allowed_to_send",
                    2: "peer_not_allowed_to_send",
                    255: None
                }
            ),
        ]


Extension.add_payload_type(0x000f, Heartbeat)


class EllipticCurves(Protocol):
    """
    Handle Elliptic Curves extension
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            VectorListUInt16Field(
                "elliptic_curve_list",
                item_class=UInt16Field,
                item_class_args=[None, None]
            ),
        ]

Extension.add_payload_type(0x000a, EllipticCurves)


class EcPointFormats(Protocol):
    """
    Handle Elliptic Curves Point Format extension
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            VectorListUInt8Field(
                "point_format_list",
                item_class=UInt8Field,
                item_class_args=[None, None]
            ),
        ]

Extension.add_payload_type(0x000b, EcPointFormats)


class SignatureAlgorithms(Protocol):
    """
    Handle Signature Algorithm extension
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            VectorListUInt16Field(
                "supported_signature_algorithms",
                item_class=SignatureAndHashAlgorithmField,
                item_class_args=[None, None]
            ),
        ]

Extension.add_payload_type(0x000d, SignatureAlgorithms)


class SessionTicketTLS(Protocol):
    """
    Handle Session Ticket extension
    """
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            VectorUInt16Field("data"),
        ]

    @classmethod
    def decode(cls, data, connection_state=None, payload_auto_decode=True):
        obj = cls(
            connection_state=connection_state
        )
        if len(data) > 0:
            data = obj.dissect(data)

        return (obj, data)

    def encode(self):
        if len(self.data) == 0:
            return b""
        else:
            return self.assemble()

Extension.add_payload_type(0x0023, SessionTicketTLS)
