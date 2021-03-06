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
import pwsr.errors as errors
import pwsr.scripts as scripts


def get_arg_parser():
    version = pwsr.__version__
    parser = argparse.ArgumentParser(
        description="pwsr-search version {0}".format(version)
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
        "--hide",
        dest="hide",
        default=False,
        action="store_true",
        help="Replace password with *'s"
    )

    parser.add_argument(
        "--list",
        dest="list",
        default=False,
        action="store_true",
        help="List All Password Safe entries"
    )

    parser.add_argument(
        "key",
        metavar="KEY",
        nargs="?",
        default=None,
        help="The search key. Example: 'gmail'"
    )

    return parser


def validate_params(argparser, **kwargs):
    args = kwargs['args']

    if not (kwargs['dbfn'] and kwargs['dbpw']):
        error = "Must provide both a pwsafe database and a password either."
        raise scripts.ArgumentError(error, show_help=True)

    if not (kwargs['key'] or args.list):
        error = "Must provide a pwsafe key to search for or --list."
        raise scripts.ArgumentError(error, show_help=True)


def clip_password(password):
    pyperclip.copy(str(password))


def main():
    # Parse the commandline arguments
    argparser = get_arg_parser()
    args = argparser.parse_args()

    # Attempt to load a pwsafe-remote configuration file
    config  = scripts.load_conf()

    # Extract pwsafe-remote parameters
    dbfn    = args.dbfn or config.get('PWDB')
    dbfn    = utils.abspath(dbfn)
    dbpw    = args.dbpw or config.get('PWDB_KEY')
    key     = args.key
    hide    = args.hide

    try:
        # Attempt to validate input parameters
        validate_params(argparser, dbfn=dbfn, dbpw=dbpw, key=key, args=args)

        # Parse the pwsafe database
        pwsafe = db.parse(dbfn, dbpw)

        if args.list:
            scripts.print_records(pwsafe, hide)
        else:
            # Find records
            records = utils.find_record(pwsafe, key, multiple=True)
            scripts.print_records(records, hide)
    except scripts.ArgumentError as ex:
        if ex.show_help:
            argparser.print_help()
        scripts.error(ex, kill=True)
    except errors.KeyLookupError as ex:
        scripts.error(ex, kill=True)

    sys.exit(scripts.EXIT_SUCCESS)

if __name__ == "__main__":
    main()
