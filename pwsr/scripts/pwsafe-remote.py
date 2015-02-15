#!/usr/bin/env python

# builtin
import sys
import argparse
import json

# external
import pyperclip

# internal
import pwsr
import pwsr.db as db
import pwsr.utils as utils

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


def error(msg):
    print "[!]", str(msg)


def get_arg_parser():
    version = pwsr.__version__
    parser = argparse.ArgumentParser(
        description="PasswordSafe - Remote - Version {0}".format(version)
    )

    parser.add_argument(
        "--db",
        dest="dbfn",
        default=None,
        help="Path to PasswordSafe Database File"
    )

    parser.add_argument(
        "--dbpw",
        dest="dbpw",
        default=None,
        help="Passwor dSafe Database key"
    )

    parser.add_argument(
        "--list",
        dest="list",
        default=False,
        action="store_true",
        help="List Password Safe entries"
    )

    parser.add_argument(
        "key",
        metavar="KEY",
        nargs="?",
        default=None,
        help="Password Safe entry key (Example: gmail)"
    )

    return parser


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


def validate_params(argparser, **kwargs):
    args = kwargs['args']

    if not (kwargs['dbfn'] and kwargs['dbpw']):
        error = "Must provide both a pwsafe database and a password either."
        raise ArgumentError(error, show_help=True)

    if not (kwargs['key'] or args.list):
        error = "Must provide a pwsafe key to look up, or --list"
        raise ArgumentError(error, show_help=True)


def list(dbfn, pwsafe):
    print "PasswordSafe entries: %s" % (dbfn)
    for entry in pwsafe:
        print entry


def print_record(record):
    title = record.title
    username = record.username
    password = record.password

    pwstr = "*" * len(password)
    out = "[{0}] [{1}] [{2}]"
    out = out.format(title, username, pwstr)

    print out


def find_record(pwsafe, key):
    try:
        record = pwsafe[key]
        records = [record]
    except KeyError:
        records = pwsafe.search(key)

    return records[0]


def clip_password(password):
    pyperclip.copy(str(password))


def main():
    # Parse the commandline arguments
    argparser = get_arg_parser()
    args = argparser.parse_args()

    # Attempt to load a pwsafe-remote configuration file
    config  = load_conf()

    # Extract pwsafe-remote parameters
    dbfn    = args.dbfn or config.get('PWDB')
    dbfn    = utils.abspath(dbfn)
    dbpw    = args.dbpw or config.get('PWDB_KEY')
    key     = args.key

    # Attempt to validate input parameters
    try:
        validate_params(argparser, dbfn=dbfn, dbpw=dbpw, key=key, args=args)
        pwsafe = db.parsedb(dbfn, dbpw)

        if args.list:
            # List all records
            list(dbfn, pwsafe)
        else:
            # Find record
            record = find_record(pwsafe, key)
            print_record(record)
            clip_password(record.password)

        # Found the record. Exit cleanly
        sys.exit(EXIT_SUCCESS)
    except ArgumentError as ex:
        if ex.show_help:
            argparser.print_help()
        error(ex)
    except IndexError:
        msg = "Cannot find entry for '{0}'".format(key)
        error(msg)

    # If we got here, something went wrong
    sys.exit(EXIT_FAILURE)


if __name__ == "__main__":
    main()
