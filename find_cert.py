#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

import sys
import subprocess
import glob
import re
import hashlib
from CertTOC import CertTOC
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Search certificate database for a certificate which contains the proper data.")
parser.add_argument("--tocdb", metavar = "filename", type = str, default = "certs/toc.sqlite3", help = "Specifies database file that contains the certificate TOC. Defaults to %(default)s.")
parser.add_argument("searchstring", help = "Search for this pattern within the OpenSSL text representation of the certificate.")
args = parser.parse_args(sys.argv[1:])

toc = CertTOC(args.tocdb)
cert_count = toc.certificate_count
regex = re.compile(args.searchstring, flags = re.MULTILINE | re.IGNORECASE)
for (certno, der_cert) in enumerate(toc.get_all_certificates()):
	if (certno % 100) == 0:
		print("Searching %d of %d (%.1f%%)..." % (certno, cert_count, certno / cert_count * 100))
	cert_text = subprocess.check_output([ "openssl", "x509", "-inform", "der", "-text", "-noout" ], input = der_cert).decode()
	if regex.search(cert_text):
		cert_pem = subprocess.check_output([ "openssl", "x509", "-inform", "der" ], input = der_cert).decode()
		print(cert_pem)
		print(cert_text)
		print(hashlib.sha256sum(der_cert).hexdigest())
		sys.exit(0)
