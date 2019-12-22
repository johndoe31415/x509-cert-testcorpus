#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

import sys
import subprocess
import glob
import re
from CertDB import CertDB
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Search certificate database for a certificate which contains the proper data.")
parser.add_argument("-d", "--dbfile", metavar = "filename", type = str, default = "domainnames.sqlite3", help = "Specifies database file that contains the domain names to scrape. Defaults to %(default)s.")
parser.add_argument("searchstring", help = "Search for this pattern within the OpenSSL text representation of the certificate.")
args = parser.parse_args(sys.argv[1:])

regex = re.compile(args.searchstring, flags = re.MULTILINE)
for filename in glob.glob("certs/[0-9a-f][0-9a-f][0-9a-f].db"):
	certdb = CertDB(filename)
	for cert in certdb.get_all():
		cert_text = subprocess.check_output([ "openssl", "x509", "-inform", "der", "-text", "-noout" ], input = cert.der_cert).decode()
		if regex.search(cert_text):
			cert_pem = subprocess.check_output([ "openssl", "x509", "-inform", "der" ], input = cert.der_cert).decode()
			print(cert.domainname)
			print(cert_pem)
			print(cert_text)
			sys.exit(0)
