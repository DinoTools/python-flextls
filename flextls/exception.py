from flextls import helper


class NotEnoughData(IOError):
    """
    Not enough data to decode the next record or field.
    """
    pass


class WrongProtocolVersion(IOError):
    """
    Raised during a connection if the server/client returns a wrong protocol version.

    :param String msg: Message
    :param flextls.protocol.Protocol record: The decoded record
    :param Integer protocol_version: Internal ID of the expected protocol version
    """
    def __init__(self, msg=None, record=None, protocol_version=None):
        if msg is None:
            msg = "Wrong protocol version"
            msg_info = []
            if protocol_version:
                msg_info.append(
                    "Expected: %s" % helper.get_version_name(protocol_version)
                )
            if record:
                tmp_version = helper.get_version_by_version_id((
                    record.version.major,
                    record.version.minor
                ))
                msg_info.append(
                    "Got: %s" % helper.get_version_name(tmp_version)
                )

            if len(msg_info) > 0:
                msg += " (%s)" % ", ".join(msg_info)

        IOError.__init__(self, msg)
        self.record = record
        self.protocol_version = protocol_version