
class InvalidPasswordError(Exception):
    pass


class KeyLookupError(Exception):
    def __init__(self, message=None, key=None):
        super(KeyLookupError, self).__init__(message)
        self.key = key