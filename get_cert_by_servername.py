#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

import sys
from CertTOC import CertTOC
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Search certificate database for a certificate which contains the proper data.")
parser.add_argument("-t", "--toc-dbfile", metavar = "filename", type = str, default = "certs/toc.sqlite3", help = "Specifies database file that contains the TOC. Defaults to %(default)s.")
parser.add_argument("domainname", type = str, help = "Domain name to dump certificates of")
args = parser.parse_args(sys.argv[1:])

toc = CertTOC(args.toc_dbfile)
connections = toc.get_connections_by_servername(args.domainname)
for connection in connections:
	CertTOC.dump_connection(connection)
