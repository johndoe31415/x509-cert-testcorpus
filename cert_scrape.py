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
from CertDatabase import CertDatabase
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Scrape certificates from websites.")
parser.add_argument("-d", "--domainname-dbfile", metavar = "filename", type = str, default = "certs/domainnames.sqlite3", help = "Specifies database file that contains the domain names to scrape. Defaults to %(default)s.")
parser.add_argument("-g", "--gracetime", metavar = "secs", type = float, default = 1, help = "Gracetime between scrapings of different domains, in seconds. Defaults to %(default).1f seconds.")
parser.add_argument("-p", "--parallel", metavar = "processes", type = int, default = 20, help = "Numer of concurrent processes that scrape. Defaults to %(default)d.")
parser.add_argument("-t", "--timeout", metavar = "secs", type = int, default = 15, help = "Timeout after which connection is discarded, in seconds. Defaults to %(default)d.")
parser.add_argument("-a", "--maxage", metavar = "days", type = int, default = 365, help = "Maximum age after which another attempt is retried, in days. Defaults to %(default)d.")
parser.add_argument("-l", "--limit", metavar = "count", type = int, help = "Quit after this amount of calls.")
parser.add_argument("-c", "--certdb", metavar = "path", type = str, default = "certs", help = "Specifies the path of the certificate database. Defaults to %(default)s.")
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
		self._db = sqlite3.connect(self._args.domainname_dbfile)
		self._cursor = self._db.cursor()
		self._domainnames = [ ]
		self._total_domain_count = 0
		self._cert_retriever = CertRetriever(self._args.timeout)
		self._certdb = CertDatabase(self._args.certdb)
		self._update_local_database()

	def _update_local_database(self):
		print("Updating local index...")
		for (domainname_id, (servername, fetch_timestamp)) in enumerate(self._certdb.get_most_recent_connections()):
			if (domainname_id % 1000) == 0:
				print(domainname_id)

			row = self._db.execute("SELECT last_attempted_timet FROM domainnames WHERE domainname = ?;", (servername, )).fetchone()
			if row is None:
				# Servername not yet known in domainnames.sqlite3, insert it.
				self._db.execute("INSERT INTO domainnames (domainname, last_successful_timet, last_attempted_timet, last_result) VALUES (?, ?, ?, 'ok');", (servername, fetch_timestamp, fetch_timestamp))
				print("ins")
			else:
				last_timestamp_domainnames = row[0]
				if last_timestamp_domainnames < fetch_timestamp:
					# We have a newer one in the actual dataset, update metadata database
					self._db.execute("UPDATE domainnames SET last_successful_timet = ?, last_attempted_timet = ?, last_result = 'ok' WHERE domainname = ?;", (fetch_timestamp, fetch_timestamp, servername))

	def _worker(self, work_queue, result_queue):
		while True:
			next_job = work_queue.get()
			if next_job is None:
				break

			domainname = next_job
			scraped_cert = self._cert_retriever.retrieve(domainname)
			result = (next_job, scraped_cert)
			result_queue.put(result)

	def _feeder(self, work_queue, result_queue):
		class BreakFreeException(Exception): pass

		fed_items = 0
		try:
			random.shuffle(self._domainnames)
			for domainname in self._domainnames:
				fed_items += 1
				work_queue.put(domainname)
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

			(domainname, (resultcode, der_certs)) = next_result
			processed_count += 1
			count_by_return[resultcode] += 1

			status_str = [ ]
			for (keyword, text) in (("ok", "OK"), ("nocert", "No cert"), ("error", "Error"), ("timeout", "Timeout")):
				count = count_by_return[keyword]
				if count > 0:
					status_str.append("%s %d / %.1f%%" % (text, count, count / processed_count * 100))
			status_str = ", ".join(status_str)
			if resultcode == "ok":
				result_comment = " [%d certs]" % (len(der_certs))
			else:
				result_comment = ""
			print("%d/%d (%.1f%%): %s: %s%s (%s)" % (processed_count, self._total_domain_count, processed_count / self._total_domain_count * 100, domainname, resultcode, result_comment, status_str))

			now = round(time.time())
			if resultcode == "ok":
				self._cursor.execute("UPDATE domainnames SET last_successful_timet = ?, last_attempted_timet = ?, last_result = ? WHERE domainname = ?;", (now, now, resultcode, domainname))
				self._certdb.insert_connection(servername = domainname, fetch_timestamp = now, certs = der_certs)
				new_cert_count += 1
				if (new_cert_count % 1000) == 0:
					certdb.commit()
			else:
				self._cursor.execute("UPDATE domainnames SET last_attempted_timet = ?, last_result = ? WHERE domainname = ?;", (now, resultcode, domainname))

			if (processed_count % 2500) == 0:
				self._certdb.commit()
				self._db.commit()
		self._certdb.commit()
		self._db.commit()

	def run(self):
		candidate_count = self._cursor.execute("SELECT COUNT(DISTINCT domainname) FROM domainnames;").fetchone()[0]

		if len(self._args.domainname) == 0:
			before_timet = time.time() - (86400 * self._args.maxage)
			print(before_timet)
			self._domainnames = [ row[0] for row in self._cursor.execute("SELECT domainname FROM domainnames WHERE last_attempted_timet < ?;", (before_timet, )).fetchall() ]
		else:
			self._domainnames = self._args.domainname
		self._total_domain_count = len(self._domainnames)

		if (self._args.limit is not None) and (self._args.limit < self._total_domain_count):
			self._total_domain_count = self._args.limit

		if self._total_domain_count == 0:
			print("Found no domainnames to scrape out of %d candidates." % (candidate_count))
			return
		else:
			print("Found %d domainnames (%d originally) to scrape out of %d candidates." % (self._total_domain_count, len(self._domainnames), candidate_count))

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
