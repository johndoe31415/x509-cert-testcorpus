#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2018-2018 Johannes Bauer
#   License: CC-0

import subprocess
import os
import hashlib

for (dirname, subdirs, files) in os.walk("raw_certs"):
	for filename in files:
		if not filename.endswith(".raw"):
			continue
		fullfilename = dirname + "/" + filename
		domain = filename[:-4]
		key = hashlib.md5(domain.encode()).hexdigest()[:3]
		outfile = "certs/%s/%s.der" % (key, filename[:-4])
		if os.path.isfile(outfile):
			continue
		try:
			try:
				os.makedirs(os.path.dirname(outfile))
			except FileExistsError:
				pass
			x509 = subprocess.check_output([ "openssl", "x509", "-in", fullfilename, "-outform", "der" ])
			with open(outfile, "wb") as f:
				f.write(x509)
		except subprocess.CalledProcessError:
			pass
