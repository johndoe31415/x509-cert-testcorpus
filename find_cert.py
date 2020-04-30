#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2020 Johannes Bauer
#   License: CC-0

import sys
import subprocess
import glob
import re
import hashlib
from CertDatabase import CertDatabase
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Search certificate database for a certificate which contains the proper data.")
parser.add_argument("-c", "--certdb", metavar = "path", type = str, default = "certs", help = "Specifies the path of the certificate database. Defaults to %(default)s.")
parser.add_argument("-n", "--nth-match", metavar = "no", type = int, default = 1, help = "Show the n-th match. Defaults to the first match.")
parser.add_argument("searchstring", help = "Search for this pattern within the OpenSSL text representation of the certificate.")
args = parser.parse_args(sys.argv[1:])

certdb = CertDatabase(args.certdb)
cert_count = certdb.certificate_count
regex = re.compile(args.searchstring, flags = re.MULTILINE | re.IGNORECASE)
matchno = 0
for (certno, der_cert) in enumerate(certdb.get_all_certificates()):
	if (certno % 100) == 0:
		print("Searching %d of %d (%.1f%%)..." % (certno, cert_count, certno / cert_count * 100))
	cert_text = subprocess.check_output([ "openssl", "x509", "-inform", "der", "-text", "-noout" ], input = der_cert).decode()
	if regex.search(cert_text):
		matchno += 1
		if matchno == args.nth_match:
			cert_pem = subprocess.check_output([ "openssl", "x509", "-inform", "der" ], input = der_cert).decode()
			print(cert_pem)
			print(cert_text)
			print("SHA256: %s" % (hashlib.sha256(der_cert).hexdigest()))
			sys.exit(0)
