class NotEnoughData(IOError):
    pass


class WrongProtocolVersion(IOError):
    def __init__(self, *args, record=None):
        IOError.__init__(self, *args)
        self.record = record