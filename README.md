# x509-cert-testcorpus
This is a corpus of about 703000 X.509 certificates in DER form, all of which
have been in public use in the wild. They have been scraped by using the Alexa
top Million list and querying every single domain name on the list on port 443
for their certificate.

The goal is to have a realistic test corpus to test tools against (shameless
plug: I did this for my X.509 Swiss Army Knife tool [x509sak](https://github.com/johndoe31415/x509sak).

Since scraping takes a long time, it made sense to me to publish the whole
corpus so other people don't have to do the scraping themselves.

## Database structure
All X.509 certificates are DER-encoded. The database naming scheme is the first
three digits of the MD5 hash of the hostname (which was also used in the SNI
X.509 extension). For example:

```
$ echo -n duckduckgo.com | md5sum
afb1343ad1b196be360351319e8aa000  -
$ ls certs/afb.db
-rw------- 1 joe joe 416K   21.12.2019 20:33:08 certs/afb.db
```

Each database is a sqlite3 file with the following schema:

```
$ sqlite3 certs/afb.db .schema
CREATE TABLE certificates (
	domainname varchar NOT NULL,
	fetched_timet integer NOT NULL,
	der_cert blob NOT NULL,
	der_hash_md5 blob NOT NULL,
	PRIMARY KEY(domainname, fetched_timet)
);
```

Certificates may be fetched for one domain multiple times. We do this so we can
preserve older certificates as well.

## Date/time of scraping
All of these certificates were scraped over about a week's worth of time
starting around 2018-10-06.

## Domain name list
To import a CSV of a domain name list, the following sources can be useful:

  * http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
  * https://siteinfo.statvoo.com/dl/top-1million-sites.csv.zip
  * http://s3-us-west-1.amazonaws.com/umbrella-static/index.html
  * Discussion here: https://gist.github.com/chilts/7229605

They are all in CSV format and can be imported using the
`import_domainname_csv.py` script.

## License
Everything in here is CC-0.
