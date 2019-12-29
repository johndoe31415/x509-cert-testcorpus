#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

import sys
from CertDatabase import CertDatabase
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Search certificate database for a certificate which contains the proper data.")
parser.add_argument("-c", "--certdb", metavar = "path", type = str, default = "certs", help = "Specifies the path of the certificate database. Defaults to %(default)s.")
parser.add_argument("domainname", type = str, help = "Domain name to dump certificates of")
args = parser.parse_args(sys.argv[1:])

certdb = CertDatabase(args.certdb)
connections = certdb.get_connections_by_servername(args.domainname)
for connection in connections:
	CertDatabase.dump_connection(connection)
