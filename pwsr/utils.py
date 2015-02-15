# builtin
import os
import contextlib
import StringIO

@contextlib.contextmanager
def ignored(*exceptions):
    """Allows you to ignore exceptions cleanly using context managers. This
    exists in Python 3.

    """
    try:
        yield
    except exceptions:
        pass


def abspath(fn):
    """Returns the absolute path to `fn`. This will expand ``~`` user home
    abbreviations.

    """
    expanded = os.path.expanduser(fn)
    abspath = os.path.abspath(expanded)
    return abspath


def ioslice(data, offset=0):
    try:
        data.seek(offset)
        return data
    except AttributeError:
        return StringIO.StringIO(data[offset:])


def bindata(data):
    try:
        return data.read()
    except AttributeError:
        return data