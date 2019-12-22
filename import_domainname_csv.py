#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2018-2018 Johannes Bauer
#   License: CC-0

import sys
import sqlite3
import contextlib
import glob
import csv
from CertDB import CertDB

def show_stats(cursor):
	(total_count, ) = cursor.execute("SELECT COUNT(*) FROM domainnames;").fetchone()
	(successful_count, ) = cursor.execute("SELECT COUNT(*) FROM domainnames WHERE last_successful_timet != 0;").fetchone()
	print("Domain name list now contains %d domainnames total, %d of which were succesfully scraped before." % (total_count, successful_count))

db = sqlite3.connect("domainnames.sqlite3")
cursor = db.cursor()
with contextlib.suppress(sqlite3.OperationalError):
	cursor.execute("""
	CREATE TABLE domainnames (
		domainname PRIMARY KEY NOT NULL,
		last_successful_timet integer NOT NULL,
		last_attempted_timet integer NOT NULL
	);
	""")

# First import domainnames from the present database
print("Processing local databases...")
for filename in glob.glob("certs/[0-9a-f][0-9a-f][0-9a-f].db"):
	certdb = CertDB(filename)

	for (domainname, timestamp) in certdb.get_domainname_timestamps():
		result = cursor.execute("SELECT last_successful_timet FROM domainnames WHERE domainname = ?;", (domainname, )).fetchone()

		if result is None:
			# Domainname not present in database
			cursor.execute("INSERT INTO domainnames (domainname, last_successful_timet, last_attempted_timet) VALUES (?, ?, ?);", (domainname, timestamp, timestamp))
		elif timestamp > result[0]:
			# Present here, but database has newer cert
			cursor.execute("UPDATE domainnames SET last_successful_timet = ?, last_attempted_timet = MAX(?, last_attempted_timet) WHERE domainname = ?;", (timestamp, timestamp, domainname))
db.commit()
show_stats(cursor)

# Then additionally import the CSV file(s) that was/were given on the command line
for filename in sys.argv[1:]:
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

