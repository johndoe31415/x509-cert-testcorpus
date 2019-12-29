#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

import sys
import os
import hashlib
import datetime

filename = sys.argv[1]
basename = os.path.basename(filename)
stat_result = os.stat(filename)
ts = datetime.datetime.utcfromtimestamp(stat_result.st_mtime)
hashval = hashlib.sha256()
with open(filename, "rb") as f:
	while True:
		chunk = f.read(1024 * 1024)
		if len(chunk) == 0:
			break
		hashval.update(chunk)
hashval = hashval.hexdigest()

print("  * Latest %s from %s" % (basename, ts.strftime("%Y-%m-%d %H:%M:%S")))
print("  * [Download link](TODO)")
print("  * File size %d bytes (%.2f GiB)" % (stat_result.st_size, stat_result.st_size / 1024 / 1024 / 1024))
print("  * SHA256 `%s`" % (hashval))
