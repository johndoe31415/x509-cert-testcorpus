#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

import sys
from CertDatabase import CertDatabase
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Search certificate database for a certificate which contains the proper data.")
parser.add_argument("-c", "--certdb", metavar = "path", type = str, default = "certs", help = "Specifies the path of the certificate database. Defaults to %(default)s.")
parser.add_argument("conn_id", type = int, help = "Connection ID to dump certificates of")
args = parser.parse_args(sys.argv[1:])

certdb = CertDatabase(args.certdb)
connection = certdb.get_connection(args.conn_id)
CertDatabase.dump_connection(connection)
