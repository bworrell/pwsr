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
        description="pwsr-get version {0}".format(version)
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


def validate_params(argparser, **kwargs):
    args = kwargs['args']

    if not (kwargs['dbfn'] and kwargs['dbpw']):
        error = "Must provide both a pwsafe database and a password either."
        raise scripts.ArgumentError(error, show_help=True)

    if not (kwargs['key'] or args.list):
        error = "Must provide a pwsafe key to look up, or --list"
        raise scripts.ArgumentError(error, show_help=True)


def print_record(record):
    title = record.title
    username = record.username
    password = record.password

    pwstr = "*" * len(password)
    out = "[{0}] [{1}] [{2}]"
    out = out.format(title, username, pwstr)

    print out


def print_records(records):
    for record in records:
        print_record(record)


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

    try:
        # Attempt to validate input parameters
        validate_params(argparser, dbfn=dbfn, dbpw=dbpw, key=key, args=args)

        # Parse the pwsafe database
        pwsafe = db.parsedb(dbfn, dbpw)

        if args.list:
            print_records(pwsafe)
        else:
            # Find record
            record = utils.find_record(pwsafe, key)
            print_record(record)
            clip_password(record.password)
    except scripts.ArgumentError as ex:
        if ex.show_help:
            argparser.print_help()
        scripts.error(ex, kill=True)
    except errors.KeyLookupError as ex:
        scripts.error(ex, kill=True)

    sys.exit(scripts.EXIT_SUCCESS)

if __name__ == "__main__":
    main()
