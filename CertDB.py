#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2018-2019 Johannes Bauer
#   License: CC-0

import os
import sqlite3
import contextlib

class CertDB():
	def __init__(self, sqlite_filename):
		self._conn = sqlite3.connect(sqlite_filename)
		self._cursor = self._conn.cursor()
		with contextlib.suppress(sqlite3.OperationalError):
			self._cursor.execute("""
			CREATE TABLE certificates (
				domainname varchar NOT NULL,
				der_cert blob NOT NULL,
				fetched_timet integer NOT NULL,
				PRIMARY KEY(domainname, fetched_timet)
			);
			""")

	def add_der_from_file(self, domainname, der_filename):
		fetched_timet = round(os.stat(der_filename).st_mtime)
		with open(der_filename, "rb") as f:
			der_cert = f.read()
		with contextlib.suppress(sqlite3.IntegrityError):
			self._cursor.execute("INSERT INTO certificates (domainname, der_cert, fetched_timet) VALUES (?, ?, ?);", (domainname, der_cert, fetched_timet))

	def commit(self):
		self._conn.commit()
