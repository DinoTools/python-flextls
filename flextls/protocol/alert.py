from flextls.field import UByteEnumField
from flextls.protocol import Protocol


class Alert(Protocol):
    def __init__(self, **kwargs):
        Protocol.__init__(self, **kwargs)
        self.fields = [
            UByteEnumField(
                "level",
                None,
                {
                    1: "warning",
                    2: "fatal",
                    255: None
                }
            ),
            UByteEnumField(
                "description",
                None,
                {
                    0: "close_notify",
                    10: "unexpected_message",
                    20: "bad_record_mac",
                    21: "decryption_failed_RESERVED",
                    22: "record_overflow",
                    30: "decompression_failure",
                    40: "handshake_failure",
                    41: "no_certificate_RESERVED",
                    42: "bad_certificate",
                    43: "unsupported_certificate",
                    44: "certificate_revoked",
                    45: "certificate_expired",
                    46: "certificate_unknown",
                    47: "illegal_parameter",
                    48: "unknown_ca",
                    49: "access_denied",
                    50: "decode_error",
                    51: "decrypt_error",
                    60: "export_restriction_RESERVED",
                    70: "protocol_version",
                    71: "insufficient_security",
                    80: "user_canceled",
                    90: "user_canceled",
                    100: "no_renegotiation",
                    110: "unsupported_extension",
                    255: None
                }
            ),
        ]

    def dissect(self, data):
        data = Protocol.dissect(self, data)
        return data
