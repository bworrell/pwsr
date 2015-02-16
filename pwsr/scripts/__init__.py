# builtin
import sys
import json

# internal
import pwsr.utils as utils

# Constants
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
DEFAULT_CONFIG_FN = utils.abspath("~/.pwsr/conf.json")

class ArgumentError(Exception):
    """An exception to be raised when invalid or incompatible arguments are
    passed into the application via the command line.

    Args:
        show_help (bool): If true, the help/usage information should be printed
            to the screen.

    Attributes:
        show_help (bool): If true, the help/usage information should be printed
            to the screen.

    """
    def __init__(self, msg=None, show_help=False):
        super(ArgumentError, self).__init__(msg)
        self.show_help = show_help


def load_conf(fn=None):
    if not fn:
        fn = DEFAULT_CONFIG_FN

    fn = utils.abspath(fn)

    try:
        with open(fn) as f:
            config = json.load(f)
    except IOError as ex:
        config = {}

    return config


def save_conf(config, fn=None):
    if not fn:
        fn = DEFAULT_CONFIG_FN

    fn = utils.abspath(fn)

    with open(fn) as f:
        json.dump(config, f)


def error(msg, kill=False):
    err = "[!] {0}\n".format(msg)
    sys.stderr.write(err)

    if kill:
        sys.exit(EXIT_FAILURE)


def info(msg):
    print "[-]", str(msg)
