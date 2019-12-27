#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2018-2019 Johannes Bauer
#   License: CC-0

import os
import sqlite3
import hashlib
import contextlib
import collections
from CertDB import CertDB

class CertTOC():
	_Connection = collections.namedtuple("Connection", [ "conn_id", "leaf_only", "fetch_timestamp", "servername", "certs" ])

	def __init__(self, sqlite_filename):
		self._conn = sqlite3.connect(sqlite_filename)
		self._cursor = self._conn.cursor()
		with contextlib.suppress(sqlite3.OperationalError):
			self._cursor.execute("""
			CREATE TABLE connections (
				conn_id integer PRIMARY KEY,
				leaf_only boolean NOT NULL,
				fetch_timestamp integer NOT NULL,
				servername varchar NOT NULL,
				cert_hashes blob NOT NULL,
				UNIQUE(servername, fetch_timestamp)
			);
			""")

		self._data_dbs = [ CertDB("%s/%02x.sqlite3" % (os.path.dirname(sqlite_filename), i)) for i in range(256) ]

	@property
	def connection_count(self):
		return self._cursor.execute("SELECT COUNT(*) FROM connections;").fetchone()[0]

	@property
	def certificate_count(self):
		return sum(data_db.certificate_count for data_db in self._data_dbs)

	def get_connection(self, conn_id):
		row = self._cursor.execute("SELECT leaf_only, fetch_timestamp, servername, cert_hashes FROM connections WHERE conn_id = ?;", (conn_id, )).fetchone()
		if row is None:
			return None
		(leaf_only, fetch_timestamp, servername, cert_hashes) = row
		cert_hashes = [ cert_hashes[i : i + 32] for i in range(0, len(cert_hashes), 32) ]
		certs = [ self._get_cert(cert_hash) for cert_hash in cert_hashes ]
		return self._Connection(conn_id = conn_id, leaf_only = leaf_only, fetch_timestamp = fetch_timestamp, servername = servername, certs = certs)

	def get_connections_by_servername(self, servername):
		conn_ids = self._cursor.execute("SELECT conn_id FROM connections WHERE servername = ? ORDER BY fetch_timestamp ASC;", (servername, )).fetchall()
		for (conn_id, ) in conn_ids:
			yield self.get_connection(conn_id)

	def _get_cert(self, cert_hash):
		dbid = cert_hash[0]
		cert_db = self._data_dbs[dbid]
		return cert_db.get_cert(cert_hash)

	def _insert_cert(self, der_cert):
		cert_hash = hashlib.sha256(der_cert).digest()
		dbid = cert_hash[0]
		cert_db = self._data_dbs[dbid]
		cert_db.add_cert(der_cert)
		return cert_hash

	def get_all_certificates(self):
		for data_db in self._data_dbs:
			yield from data_db.get_all_certificates()

	def insert_connection(self, servername, fetch_timestamp, certs, leaf_only = False):
		cert_hashes = [ self._insert_cert(cert) for cert in certs ]
		cert_hashconcat = b"".join(cert_hashes)
		with contextlib.suppress(sqlite3.IntegrityError):
			self._cursor.execute("INSERT INTO connections (leaf_only, fetch_timestamp, servername, cert_hashes) VALUES (?, ?, ?, ?);", (leaf_only, fetch_timestamp, servername, cert_hashconcat))

	def commit(self):
		for data_db in self._data_dbs:
			data_db.commit()
		self._conn.commit()

	def close(self):
		if self._conn is None:
			return
		self.commit()
		for data_db in self._data_dbs:
			data_db.close()
		self._cursor.close()
		self._conn.close()
		self._cursor = None
		self._conn = None

	def __del__(self):
		self.close()

if __name__ == "__main__":
	x = CertTOC("test/toc.sqlite3")
	x.insert_connection("foobar", 1234, [ b"foobar" ])
	x.insert_connection("foobar", 1235, [ b"foobar second", b"moo" ])
	print(x.get_connection(2))
	x.close()
