#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2018-2018 Johannes Bauer
#   License: CC-0

import sys
import sqlite3
import contextlib
import csv
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Import domain names from CSV lists and already scraped certificates.")
parser.add_argument("-d", "--domainname-dbfile", metavar = "filename", type = str, default = "certs/domainnames.sqlite3", help = "Specifies database file that contains the domain names to scrape. Defaults to %(default)s.")
parser.add_argument("--reset", action = "store_true", help = "Clear the domain name information and rely solely on the information found in the database.")
parser.add_argument("csvfiles", nargs = "*", help = "Import content of these CSV file(s).")
args = parser.parse_args(sys.argv[1:])

def show_stats(cursor):
	(total_count, ) = cursor.execute("SELECT COUNT(*) FROM domainnames;").fetchone()
	(successful_count, ) = cursor.execute("SELECT COUNT(*) FROM domainnames WHERE last_successful_timet != 0;").fetchone()
	print("Domain name list now contains %d domainnames total, %d of which were succesfully scraped before." % (total_count, successful_count))

db = sqlite3.connect(args.domainname_dbfile)
cursor = db.cursor()
with contextlib.suppress(sqlite3.OperationalError):
	cursor.execute("""
	CREATE TABLE domainnames (
		domainname PRIMARY KEY NOT NULL,
		last_successful_timet integer NOT NULL,
		last_attempted_timet integer NOT NULL,
		last_result NULL
	);
	""")

if args.reset:
	print("Resetting local database content...")
	cursor.execute("UPDATE domainnames SET last_successful_timet = 0, last_attempted_timet = 0, last_result = NULL;")

# Import the CSV file(s) that was/were given on the command line
for filename in args.csvfiles:
	print("Processing CSV %s..." % (filename))
	with open(filename) as f:
		for row in csv.reader(f):
			if len(row) != 2:
				continue
			(pos, domainname) = row

			(count, ) = cursor.execute("SELECT COUNT(*) FROM domainnames WHERE domainname = ?;", (domainname, )).fetchone()
			if count == 0:
				# We do not have this entry yet, create it.
				cursor.execute("INSERT INTO domainnames (domainname, last_successful_timet, last_attempted_timet) VALUES (?, 0, 0);", (domainname, ))
	db.commit()
	show_stats(cursor)

