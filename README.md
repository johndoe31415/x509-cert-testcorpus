# x509-cert-testcorpus
This is a corpus of about 1.74 million unique X.509 certificates, all of which
have been in public use in the wild by querying about 3.9 million different TLS
servers. They have been scraped by using server name lists like the Alexa top
Million list and querying every single host on port 443 for their certificate.

The goal is to have a realistic test corpus to test tools against (shameless
plug: I did this for my X.509 Swiss Army Knife tool [x509sak](https://github.com/johndoe31415/x509sak).

Since scraping takes a long time, it made sense to me to publish the whole
corpus so other people don't have to do the scraping themselves.

## Certificate content
Because the size of the database has outgrown GitHub (GitHub LFS is too
restrictive in the free plan and we really don't want to store the binaries
within Git), they're now hosted as a tar.gz archive here:

  * Latest certs.tar.gz from 2019-12-31 10:30:23
  * [Download link](https://www.mediafire.com/file/nvx63hfwcwsn49d/certs.tar.gz/file)
  * [Alternative download link](https://ln2.sync.com/dl/317cba7b0/wve64v7s-exsrctnc-7bs72ket-cqrbabe5)
  * File size 2054334870 bytes (1.91 GiB)
  * SHA256 `04740d4e1205a2274bed78991b20f698e36e9d2b334547e6eea66a7bc702b449`

## Database structure
The database contains a table of contents (TOC) Sqlite3 database and 256
storage Sqlite3 databases. The TOC contains SHA256 hashes over the DER encoding
of the certificates. The first byte of the SHA256 gives the number of the
storage database the actual cert can be found in. Thus, the TOC structure is:

```
CREATE TABLE connections (
	conn_id integer PRIMARY KEY,
	leaf_only boolean NOT NULL,
	fetch_timestamp integer NOT NULL,
	servername varchar NOT NULL,
	cert_hashes blob NOT NULL,
	UNIQUE(servername, fetch_timestamp)
);
```

The `leaf_only` flag indicates wether or not only the leaf (server) certificate
was stored in the database.  This is meaningful to be able to distinguish if
the server really returned only its server certificate or if it might have
returned more, but those CA certificates were not stored.

The `cert_hashes` is a binary string of concatenated SHA256 hashes that
reference the presented certificates.  It is always a multiple of 32 bytes in
length and the order is the same order in which the certificates were received
(starting from the server certificate itself at the very front).

The storage databases themselves are straightforward in their definition:

```
CREATE TABLE certificates (
	cert_sha256 blob PRIMARY KEY,
	der_cert blob NOT NULL
);
```

## Date/time of scraping
A first batch of these certificates were scraped over about a week's worth of
time starting around 2018-10-06, a second batch around 2019-12-22.

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
