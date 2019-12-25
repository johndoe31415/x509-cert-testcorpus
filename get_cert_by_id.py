#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

import sys
import datetime
import subprocess
from CertTOC import CertTOC
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Search certificate database for a certificate which contains the proper data.")
parser.add_argument("-t", "--toc-dbfile", metavar = "filename", type = str, default = "certs/toc.sqlite3", help = "Specifies database file that contains the TOC. Defaults to %(default)s.")
parser.add_argument("conn_id", type = int, help = "Connection ID to dump certificates of")
args = parser.parse_args(sys.argv[1:])

toc = CertTOC(args.toc_dbfile)
result = toc.get_connection(args.conn_id)
fetch_ts = datetime.datetime.utcfromtimestamp(result.fetch_timestamp).strftime("%Y-%m-%d %H:%M:%S")
print("Connection %d to %s fetched at %s, leaf certificates %s (%d certs)" % (result.conn_id, result.servername, fetch_ts, "only" if result.leaf_only else "and CA certificates", len(result.certs)))
for cert in result.certs:
	print(subprocess.check_output([ "openssl", "x509", "-inform", "der" ], input = cert).decode().rstrip())
