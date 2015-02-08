class NotEnoughData(IOError):
    pass


class WrongProtocolVersion(IOError):
    def __init__(self, msg=None, record=None, protocol_version=None):
        from flextls import helper
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