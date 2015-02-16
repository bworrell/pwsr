# builtin
import os
import contextlib
import StringIO

# internal
import pwsr.errors as errors


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
    """Returns a read()-able object which contains `data` starting at `offset`.

    """
    try:
        data.seek(offset)
        return data
    except AttributeError:
        return StringIO.StringIO(data[offset:])


def bindata(data):
    """Returns a binary, index-accesible version of `data`.

    If `data` is a read()-able object, it will return the str representation
    of `data`.

    """
    try:
        return data.read()
    except AttributeError:
        return data


def find_record(pwsafe, key, multiple=False):
    """Attempts to find the record in `pwsafe` which matches `key`. If the
    lookup of `key` fails, the pwsafe will be searched for a similar entry.

    Returns:
        A :class:`.PWSafeV3Record` with a title which matches (or comes close
        to matching) `key`.

    Raises:
        .KeyLookupError: If the lookup fails.

    """
    try:
        record = pwsafe[key]
        records = [record]
    except KeyError:
        records = pwsafe.search(key)

    if records:
        return records if multiple else records[0]

    error = "The PWSafe did not contain an entry for '{0}'".format(key)
    raise errors.KeyLookupError(message=error, key=key)