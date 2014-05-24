#!/usr/bin/env python

import sys
from pwsafe import PWSafeDB

def error(msg):
    print "[!]", msg
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        error("Please provide a database file and password")

    fn = sys.argv[1]
    pw = sys.argv[2]

    pwsafe = PWSafeDB()

    with open(fn, 'rb') as db:
        pwsafe.parse(db, pw)
        print pwsafe


if __name__ == "__main__":
    main()