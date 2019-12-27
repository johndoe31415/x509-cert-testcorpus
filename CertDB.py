#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2018-2019 Johannes Bauer
#   License: CC-0

import sqlite3
import hashlib
import contextlib

class CertDB():
	def __init__(self, sqlite_filename):
		self._conn = sqlite3.connect(sqlite_filename)
		self._cursor = self._conn.cursor()
		with contextlib.suppress(sqlite3.OperationalError):
			self._cursor.execute("""
			CREATE TABLE certificates (
				cert_sha256 blob PRIMARY KEY,
				der_cert blob
			);
			""")

	@property
	def certificate_count(self):
		return self._cursor.execute("SELECT COUNT(*) FROM certificates;").fetchone()[0]

	def get_all_certificates(self):
		for row in self._cursor.execute("SELECT der_cert FROM certificates;").fetchall():
			yield row[0]

	def get_cert(self, cert_sha256):
		row = self._cursor.execute("SELECT der_cert FROM certificates WHERE cert_sha256 = ?;", (cert_sha256, )).fetchone()
		if row is not None:
			return row[0]

	def add_cert(self, der_cert):
		cert_sha256 = hashlib.sha256(der_cert).digest()
		with contextlib.suppress(sqlite3.IntegrityError):
			self._cursor.execute("INSERT INTO certificates (cert_sha256, der_cert) VALUES (?, ?);", (cert_sha256, der_cert))

	def commit(self):
		self._conn.commit()

	def close(self):
		if self._conn is None:
			return
		self.commit()
		self._cursor.close()
		self._conn.close()
		self._cursor = None
		self._conn = None

	def __del__(self):
		self.close()
