#!/usr/bin/python3
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2018-2018 Johannes Bauer
#   License: CC-0

import sys
import sqlite3
import contextlib
import subprocess
import multiprocessing
import hashlib
import time
import collections
from CertDB import CertDB
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Scrape certificates from websites.")
parser.add_argument("-d", "--dbfile", metavar = "filename", type = str, default = "domainnames.sqlite3", help = "Specifies database file that contains the domain names to scrape. Defaults to %(default)s.")
parser.add_argument("-g", "--gracetime", metavar = "secs", type = float, default = 1, help = "Gracetime between scrapings of different domains, in seconds. Defaults to %(default).1f seconds.")
parser.add_argument("-p", "--parallel", metavar = "processes", type = int, default = 20, help = "Numer of concurrent processes that scrape. Defaults to %(default)d.")
parser.add_argument("-t", "--timeout", metavar = "secs", type = int, default = 15, help = "Timeout after which connection is discarded, in seconds. Defaults to %(default)d.")
parser.add_argument("-a", "--maxage", metavar = "days", type = int, default = 365, help = "Maximum age after which another attempt is retried, in days. Defaults to %(default)d.")
args = parser.parse_args(sys.argv[1:])

class Scraper():
	def __init__(self, args):
		self._args = args
		self._db = sqlite3.connect(self._args.dbfile)
		self._cursor = self._db.cursor()
		self._domainnames_by_key = None

	@staticmethod
	def _db_key(domainname):
		return hashlib.md5(domainname.encode("ascii")).hexdigest()[:3]

	def _scrape_certificate(self, domainname):
		print(domainname)
		cmd = [ "openssl", "s_client", "-connect", "%s:443" % (domainname), "-servername", domainname ]
		proc = subprocess.Popen(cmd, stdin = subprocess.DEVNULL, stdout = subprocess.PIPE, stderr = subprocess.DEVNULL)
		try:
			proc.wait(timeout = self._args.timeout)
			if proc.returncode == 0:
				stdout = proc.stdout.read()
				try:
					der_cert = subprocess.check_output([ "openssl", "x509", "-outform", "der" ], input = stdout)
					return ("ok", der_cert)
				except subprocess.CalledProcessError:
					# Did not contain certificate?
					return ("nocert", None)
			else:
				# Failed with error
				return ("error", None)
		except subprocess.TimeoutExpired:
			# Process unresponsive
			proc.kill()
			return ("timeout", None)

	def run(self):
		before_timet = time.time() - (86400 * self._args.maxage)
		domainnames = [ row[0] for row in self._cursor.execute("SELECT domainname FROM domainnames WHERE last_attempted_timet < ?;", (before_timet, )).fetchall() ]
		print("Found %d domainnames to scrape." % (len(domainnames)))

		# Group them by database key
		self._domainnames_by_key = collections.defaultdict(list)
		for domainname in domainnames:
			key = self._db_key(domainname)
			self._domainnames_by_key[key].append(domainname)
		print("Grouped domainnames into %d keys." % (len(self._domainnames_by_key)))



scraper = Scraper(args)
#scraper.run()
scraper._scrape_certificate("johannes-bauer.com")
