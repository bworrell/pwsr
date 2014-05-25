#!/usr/bin/env python

import sys
import pyperclip
from pwsafe import PWSafeDB

def error(msg):
    print "[!]", msg
    sys.exit(1)

def main():
    if len(sys.argv) != 4:
        error("Please provide a database file and password")

    fn = sys.argv[1]
    dbpw = sys.argv[2]
    key = sys.argv[3]

    pwsafe = PWSafeDB()

    with open(fn, 'rb') as db:
        pwsafe.parse(db, dbpw)
        pwrecord = pwsafe[key]

        if pwrecord:
            print "[%s] [%s]" % (pwrecord.title, pwrecord.username)
            pyperclip.copy(str(pwrecord.password))
        else:
            print "Cannot find entry for [%s]" % (key)


if __name__ == "__main__":
    main()