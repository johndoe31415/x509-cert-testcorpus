# x509-cert-testcorpus
This is a corpus of about 703000 X.509 certificates in DER form, all of which
have been in public use in the wild. They have been scraped by using the Alexa
top Million list and querying every single domain name on the list on port 443
for their certificate.

The goal is to have a realistic test corpus to test tools against (shameless
plug: I did this for my X.509 Swiss Army Knife tool [x509sak](https://github.com/johndoe31415/x509sak).

Since scraping takes a long time, it made sense to me to publish the whole
corpus so other people don't have to do the scraping themselves.

## Directory structure
All X.509 certificates are DER-encoded. The subdirectory naming scheme is the
first three digits of the MD5 hash of the hostname (which was also used in the
SNI X.509 extension). For example:

```
$ echo -n duckduckgo.com | md5sum
afb1343ad1b196be360351319e8aa000  -
$ ls certs/afb/duck*
-rw------- 1 joe joe 1,6K   12.10.2018 12:10:36 certs/afb/duckduckgo.com.der
```

## Date/time of scraping
All of these certificates were scraped over about a week's worth of time
starting around 2018-10-06.

## License
Everything in here is CC-0.
