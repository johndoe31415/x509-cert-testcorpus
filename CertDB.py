#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2018-2019 Johannes Bauer
#   License: CC-0

import os
import sqlite3
import hashlib
import contextlib
import collections

class CertDB():
	_DBEntry = collections.namedtuple("DBEntry", [ "domainname", "fetched_timet", "der_hash_md5", "der_cert" ])

	def __init__(self, sqlite_filename):
		self._conn = sqlite3.connect(sqlite_filename)
		self._cursor = self._conn.cursor()
		with contextlib.suppress(sqlite3.OperationalError):
			self._cursor.execute("""
			CREATE TABLE certificates (
				domainname varchar NOT NULL,
				fetched_timet integer NOT NULL,
				der_cert blob NOT NULL,
				der_hash_md5 blob NOT NULL,
				PRIMARY KEY(domainname, fetched_timet)
			);
			""")

	def get_all(self):
		for data in self._cursor.execute("SELECT domainname, fetched_timet, der_hash_md5, der_cert FROM certificates;").fetchall():
			yield self._DBEntry(*data)

	def get_domainname_timestamps(self):
		return self._cursor.execute("SELECT domainname, MAX(fetched_timet) FROM certificates GROUP BY domainname;").fetchall()

	def add_der(self, domainname, fetched_timet, der_cert):
		der_hash_md5 = hashlib.md5(der_cert).digest()
		with contextlib.suppress(sqlite3.IntegrityError):
			self._cursor.execute("INSERT INTO certificates (domainname, fetched_timet, der_cert, der_hash_md5) VALUES (?, ?, ?, ?);", (domainname, fetched_timet, der_cert, der_hash_md5))

	def add_der_from_file(self, domainname, der_filename):
		fetched_timet = round(os.stat(der_filename).st_mtime)
		with open(der_filename, "rb") as f:
			der_cert = f.read()
		self.add_der(domainname, fetched_timet, der_cert)

	def commit(self):
		self._conn.commit()

	def close(self):
		self.commit()
		self._cursor.close()
		self._conn.close()

	def __del__(self):
		self.close()
