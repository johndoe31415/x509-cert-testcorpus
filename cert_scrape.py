#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2018-2018 Johannes Bauer
#   License: CC-0

import subprocess
import csv
import hashlib
import collections
import random
import time
import os
import threading

thread_cnt = 12
threads = threading.Semaphore(thread_cnt)
gracetime = 0.5
#max_entries = 10000; randomized = False
max_entries = None; randomized = True
Entry = collections.namedtuple("Entry", [ "tld", "key", "outfile", "crtfile" ])
ctr = collections.Counter()

entries = [ ]
with open("top-1m.csv") as f:
	for line in csv.reader(f):
		if len(line) == 2:
			(rank, tld) = line
			key = hashlib.md5(tld.encode()).hexdigest()[:3]
			outfile = "raw_certs/%s/%s.raw" % (key, tld)
			crtfile = "certs/%s/%s.der" % (key, tld)
			entry = Entry(tld = tld, key = key, outfile = outfile, crtfile = crtfile)
			ctr[key] += 1
			entries.append(entry)
			if (max_entries is not None) and (len(ctr) == max_entries):
				break
print("Most common keys:", ctr.most_common(10))
print("Key directories :", len(ctr))

def process_entry(entry):
	if os.path.isfile(entry.outfile) or os.path.isfile(entry.crtfile):
		print("%s: skipped" % (entry.tld))
		threads.release()
		return False

	# Create output file first
	directory = os.path.dirname(entry.outfile)
	try:
		os.makedirs(directory)
	except FileExistsError:
		pass

	with open(entry.outfile, "wb") as outfile:
		cmd = [ "openssl", "s_client", "-connect", "%s:443" % (entry.tld), "-servername", entry.tld ]
		proc = subprocess.Popen(cmd, stdin = subprocess.DEVNULL, stdout = outfile, stderr = subprocess.STDOUT)
		try:
			proc.wait(timeout = 15)
			if proc.returncode == 0:
				print("%s: success" % (entry.tld))
			else:
				print("%s: failed" % (entry.tld))
		except subprocess.TimeoutExpired:
			proc.kill()
			print("%s: timed out" % (entry.tld))
	time.sleep(gracetime)
	threads.release()
	return True

if randomized:
	random.shuffle(entries)
else:
	entries.sort()
for entry in entries:
	threads.acquire()
	thread = threading.Thread(target = process_entry, args = (entry, ))
	thread.start()

for i in range(thread_cnt):
	threads.acquire()
