#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

import sys
from CertDatabase import CertDatabase
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Sanity check a certificate database.")
parser.add_argument("-s", "--stats-only", action = "store_true", help = "Only print stats, do not do any modification of the database.")
parser.add_argument("--skip-connection-check", action = "store_true", help = "Do not check if all connections have associated certificate data.")
parser.add_argument("--skip-unused-certificate-check", action = "store_true", help = "Do not check if there are dangling certificates that are not referenced in the TOC.")
parser.add_argument("--skip-optimization", action = "store_true", help = "Do not optimize databases as the last step.")
parser.add_argument("-c", "--certdb", metavar = "path", type = str, default = "certs", help = "Specifies the path of the certificate database. Defaults to %(default)s.")
args = parser.parse_args(sys.argv[1:])

certdb = CertDatabase(args.certdb)
(conn_count, cert_count) = (certdb.connection_count, certdb.certificate_count)
print("Analyzing database with %d connections and %d certificates." % (conn_count, cert_count))
if args.stats_only:
	sys.exit(0)

if not args.skip_connection_check:
	print("Checking for connections with missing certificates...")
	for (conn_number, connection) in enumerate(certdb.get_all_connections()):
		if (conn_number % 10000) == 0:
			print("Connection: %d / %d (%.1f%%)" % (conn_number, conn_count, conn_number / conn_count * 100))
		if any(cert is None for cert in connection.certs):
			print("Missing certificates for connection %d, removing connection." % (connection.conn_id))
			certdb.remove_connection(connection.conn_id)

if not args.skip_unused_certificate_check:
	print("Checking for unused certificates in database...")
	referenced_certs = certdb.get_all_referenced_hashes()
	print("%d certificates are referenced within the TOC." % (len(referenced_certs)))
	stored_certs = certdb.get_all_stored_hashes()
	print("%d certificates are in storage." % (len(stored_certs)))
	unused_hashes = stored_certs - referenced_certs
	if len(unused_hashes) == 0:
		print("All certificates are properly referenced in the TOC.")
	else:
		print("There are %d dangling certificates with no reference in the TOC, removing them." % (len(unused_hashes)))
		for unused_hash in unused_hashes:
			certdb.remove_cert_from_storage(unused_hash)

if not args.skip_optimization:
	print("Optimizing database...")
	certdb.optimize()
