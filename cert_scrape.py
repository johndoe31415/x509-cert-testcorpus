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
import random
import re
from CertTOC import CertTOC
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Scrape certificates from websites.")
parser.add_argument("-d", "--dbfile", metavar = "filename", type = str, default = "domainnames.sqlite3", help = "Specifies database file that contains the domain names to scrape. Defaults to %(default)s.")
parser.add_argument("-g", "--gracetime", metavar = "secs", type = float, default = 1, help = "Gracetime between scrapings of different domains, in seconds. Defaults to %(default).1f seconds.")
parser.add_argument("-p", "--parallel", metavar = "processes", type = int, default = 20, help = "Numer of concurrent processes that scrape. Defaults to %(default)d.")
parser.add_argument("-t", "--timeout", metavar = "secs", type = int, default = 15, help = "Timeout after which connection is discarded, in seconds. Defaults to %(default)d.")
parser.add_argument("-a", "--maxage", metavar = "days", type = int, default = 365, help = "Maximum age after which another attempt is retried, in days. Defaults to %(default)d.")
parser.add_argument("-l", "--limit", metavar = "count", type = int, help = "Quit after this amount of calls.")
parser.add_argument("--tocdb", metavar = "filename", type = str, default = "certs/toc.sqlite3", help = "Specifies certificate database TOC file. Defaults to %(default)s.")
parser.add_argument("domainname", nargs = "*", help = "When explicit domain names are supplied on the command line, only those are scraped and the max age is disregarded.")
args = parser.parse_args(sys.argv[1:])

class CertRetriever():
	_CERT_RE = re.compile("-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----", flags = re.MULTILINE)

	def __init__(self, timeout):
		self._timeout = timeout

	def _parse_certs(self, openssl_output):
		output_text = openssl_output.decode("utf-8", errors = "replace")
		certs = [ ]
		for match in self._CERT_RE.finditer(output_text):
			cert_text = match.group(0).encode("ascii")
			der_cert = subprocess.check_output([ "openssl", "x509", "-outform", "der" ], input = cert_text)
			certs.append(der_cert)
		return certs

	def retrieve(self, servername, port = 443):
		cmd = [ "openssl", "s_client", "-showcerts", "-connect", "%s:%d" % (servername, port), "-servername", servername ]
		proc = subprocess.Popen(cmd, stdin = subprocess.DEVNULL, stdout = subprocess.PIPE, stderr = subprocess.DEVNULL)
		try:
			proc.wait(timeout = self._timeout)
			if proc.returncode == 0:
				stdout = proc.stdout.read()
				try:
					der_certs = self._parse_certs(stdout)
					return ("ok", der_certs)
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


class Scraper():
	def __init__(self, args):
		self._args = args
		self._db = sqlite3.connect(self._args.dbfile)
		self._cursor = self._db.cursor()
		self._domainnames_by_key = None
		self._total_domain_count = 0
		self._cert_retriever = CertRetriever(self._args.timeout)
		self._toc = CertTOC(self._args.tocdb)

	@staticmethod
	def _db_key(domainname):
		return hashlib.md5(domainname.encode("ascii")).hexdigest()[:3]

	def _worker(self, work_queue, result_queue):
		while True:
			next_job = work_queue.get()
			if next_job is None:
				break

			(key, domainname) = next_job
			scraped_cert = self._cert_retriever.retrieve(domainname)
			result = (next_job, scraped_cert)
			result_queue.put(result)

	def _feeder(self, work_queue, result_queue):
		class BreakFreeException(Exception): pass

		fed_items = 0
		try:
			for (key, domainnames) in sorted(self._domainnames_by_key.items()):
				random.shuffle(domainnames)
				for domainname in domainnames:
					fed_items += 1
					work_queue.put((key, domainname))
					if (self._args.limit is not None) and (fed_items >= self._args.limit):
						raise BreakFreeException()
		except BreakFreeException:
			pass

		# Finally kill all workers
		for i in range(self._args.parallel):
			work_queue.put(None)

	def _eater(self, work_queue, result_queue):
		processed_count = 0
		new_cert_count = 0
		count_by_return = collections.Counter()

		while True:
			next_result = result_queue.get()
			if next_result is None:
				break

			((key, domainname), (resultcode, der_certs)) = next_result
			processed_count += 1
			count_by_return[resultcode] += 1

			status_str = [ ]
			for (keyword, text) in (("ok", "OK"), ("nocert", "No cert"), ("error", "Error"), ("timeout", "Timeout")):
				count = count_by_return[keyword]
				if count > 0:
					status_str.append("%s %d / %.1f%%" % (text, count, count / processed_count * 100))
			status_str = ", ".join(status_str)
			print("%d/%d (%.1f%%): [%s] %s: %s (%s)" % (processed_count, self._total_domain_count, processed_count / self._total_domain_count * 100, key, domainname, resultcode, status_str))

			now = round(time.time())
			if resultcode == "ok":
				self._cursor.execute("UPDATE domainnames SET last_successful_timet = ?, last_attempted_timet = ?, last_result = ? WHERE domainname = ?;", (now, now, resultcode, domainname))
				self._toc.insert_connection(servername = domainname, fetch_timestamp = now, certs = der_certs)
				new_cert_count += 1
				if (new_cert_count % 1000) == 0:
					certdb.commit()
			else:
				self._cursor.execute("UPDATE domainnames SET last_attempted_timet = ?, last_result = ? WHERE domainname = ?;", (now, resultcode, domainname))

			if (processed_count % 2500) == 0:
				self._toc.commit()
				self._db.commit()
		self._toc.commit()
		self._db.commit()

	def run(self):
		if len(self._args.domainname) == 0:
			before_timet = time.time() - (86400 * self._args.maxage)
			domainnames = [ row[0] for row in self._cursor.execute("SELECT domainname FROM domainnames WHERE last_attempted_timet < ?;", (before_timet, )).fetchall() ]
		else:
			domainnames = self._args.domainname
		self._total_domain_count = len(domainnames)
		if (self._args.limit is not None) and (self._args.limit < self._total_domain_count):
			self._total_domain_count = self._args.limit
		print("Found %d domainnames to scrape." % (self._total_domain_count))

		# Group them by database key
		self._domainnames_by_key = collections.defaultdict(list)
		for domainname in domainnames:
			key = self._db_key(domainname)
			self._domainnames_by_key[key].append(domainname)
		print("Grouped domainnames into %d keys." % (len(self._domainnames_by_key)))

		# Initialize subprocess queues
		work_queue = multiprocessing.Queue(maxsize = 100)
		result_queue = multiprocessing.Queue(maxsize = 100)

		# Start worker processes
		processes = [ multiprocessing.Process(target = self._worker, args = (work_queue, result_queue)) for i in range(self._args.parallel) ]
		for process in processes:
			process.start()

		# Start feeder and eater process
		feeder = multiprocessing.Process(target = self._feeder, args = (work_queue, result_queue))
		eater = multiprocessing.Process(target = self._eater, args = (work_queue, result_queue))
		feeder.start()
		eater.start()

		# Wait for feeder to finish seeding
		feeder.join()

		# Then wait for all workers to finish
		for process in processes:
			process.join()

		# Finally, quit the eater process as well
		result_queue.put(None)
		eater.join()

scraper = Scraper(args)
scraper.run()
