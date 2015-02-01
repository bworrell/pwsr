#!/usr/bin/env python

# builtin
import sys
import argparse
import json
import os.path

# external
import pyperclip

# internal
import pwsr
import pwsr.db as db

EXIT_SUCCESS = 0
EXIT_FAILURE = 1

DEFAULT_CONFIG_FN = os.path.expanduser("~/.pwsr/conf.json")

def error(msg):
    print "[!]", msg
    sys.exit(EXIT_FAILURE)


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

    fn = get_path(fn)

    try:
        with open(fn) as f:
            config = json.load(f)
    except IOError as ex:
        config = {}

    return config

def get_path(fn):
    expanded = os.path.expanduser(fn)
    abspath = os.path.abspath(expanded)
    return abspath

def main():
    argparser = get_arg_parser()
    args = argparser.parse_args()

    config  = load_conf()

    dbfn    = args.dbfn or config.get('PWDB')
    dbpw    = args.dbpw or config.get('PWDB_KEY')
    key     = args.key

    if not (dbfn and dbpw):
        argparser.print_help()
        sys.exit(EXIT_FAILURE)

    if not (key or args.list):
        argparser.print_help()
        sys.exit(EXIT_FAILURE)

    dbfn = get_path(dbfn)
    pwsafe = db.PWSafeDB()
    with open(dbfn, 'rb') as database:
        pwsafe.parse(database, dbpw)

    if args.list:
        print "PasswordSafe entries: %s" % (dbfn)
        for entry in pwsafe:
            print entry
    else:
        pwrecord = pwsafe[key]
        if pwrecord:
            print "[%s] [%s]" % (pwrecord.title, pwrecord.username)
            pyperclip.copy(str(pwrecord.password))
        else:
            print "Cannot find entry for [%s]" % (key)


if __name__ == "__main__":
    main()
