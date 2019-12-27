#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

import sys
from CertTOC import CertTOC
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Search certificate database for a certificate which contains the proper data.")
parser.add_argument("-t", "--toc-dbfile", metavar = "filename", type = str, default = "certs/toc.sqlite3", help = "Specifies database file that contains the TOC. Defaults to %(default)s.")
parser.add_argument("conn_id", type = int, help = "Connection ID to dump certificates of")
args = parser.parse_args(sys.argv[1:])

toc = CertTOC(args.toc_dbfile)
connection = toc.get_connection(args.conn_id)
CertTOC.dump_connection(connection)
