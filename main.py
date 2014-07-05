#!/usr/bin/env python

import sys
import argparse
import pyperclip
from pwsafe import PWSafeDB
import settings

__version__ = "0.1"

EXIT_ERROR = 1

def error(msg):
    print "[!]", msg
    sys.exit(EXIT_ERROR)

def main():
    parser = argparse.ArgumentParser(description="PasswordSafe - Remote - "
                                                 "Version %s" % __version__)
    parser.add_argument("--db", dest="dbfn", default=None,
                        help="Path to PasswordSafe Database File")
    parser.add_argument("--dbpw", dest="dbpw", default=None,
                        help="PasswordSafe Database key")
    parser.add_argument("--list", dest="list", default=False,
                        action="store_true", help="List PasswordSafe entries")
    parser.add_argument("key", metavar="KEY", nargs="?", default=None,
                        help="PasswordSafe entry key")
    args = parser.parse_args()

    dbfn    = args.dbfn or settings.__dict__.get("PWDB")
    dbpw    = args.dbpw or settings.__dict__.get("PWDBKEY")
    key     = args.key

    if not (dbfn or dbpw):
        parser.print_help()
        sys.exit(EXIT_ERROR)

    if not (key or args.list):
        parser.print_help()
        sys.exit(EXIT_ERROR)

    pwsafe = PWSafeDB()
    with open(dbfn, 'rb') as db:
        pwsafe.parse(db, dbpw)

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
