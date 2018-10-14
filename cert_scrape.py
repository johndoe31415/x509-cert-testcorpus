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
#max_entries = 10000
max_entries = None
Entry = collections.namedtuple("Entry", [ "tld", "key", "outfile", "crtfile" ])
ctr = collections.Counter()

entries = [ ]
with open("top-1m.csv") as f:
	for (lineno, line) in enumerate(csv.reader(f), 1):
		if len(line) == 2:
			(rank, tld) = line
			key = hashlib.md5(tld.encode()).hexdigest()[:3]
			outfile = "raw_certs/%s/%s.raw" % (key, tld)
			crtfile = "certs/%s/%s.der" % (key, tld)
			entry = Entry(tld = tld, key = key, outfile = outfile, crtfile = crtfile)
			ctr[key] += 1
			if (not os.path.isfile(entry.outfile)) and (not os.path.isfile(entry.crtfile)):
				entries.append(entry)
		if (max_entries is not None) and (lineno >= max_entries):
			break
print("Most common keys:", ctr.most_common(10))
print("Key directories :", len(ctr))
print("Entries total   :", len(entries))

def log(entry, result, entryid, entrycnt):
	print("%5.1f%% %6d/%6d %s: %s" % (entryid / entrycnt * 100, entryid, entrycnt, entry.tld, result))

def process_entry(entry, entryid, entrycnt):
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
				log(entry, "success", entryid, entrycnt)
			else:
				log(entry, "failed", entryid, entrycnt)
		except subprocess.TimeoutExpired:
			proc.kill()
			log(entry, "timed out", entryid, entrycnt)
	time.sleep(gracetime)
	threads.release()
	return True

random.shuffle(entries)

for (entryid, entry) in enumerate(entries):
	threads.acquire()
	thread = threading.Thread(target = process_entry, args = (entry, entryid, len(entries)))
	thread.start()

for i in range(thread_cnt):
	threads.acquire()
