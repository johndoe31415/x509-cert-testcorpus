#!/bin/bash -e
#	x509-cert-testcorpus - X.509 certificate test corpus
#	Copyright (C) 2019-2019 Johannes Bauer
#   License: CC-0

echo -n "Really rebuild all Sqlite3 databases (y/n)? "
read yn
if [ "$yn" != "Y" ] && [ "$yn" != "y" ]; then
	echo "Aborted."
	exit 1
fi

for SQLITE_DB in certs/*.sqlite3; do
	if [ ! -f "$SQLITE_DB" ]; then
		continue
	fi
	echo "$SQLITE_DB"
	rm -f temp_db.sqlite3
	sqlite3 "$SQLITE_DB" .dump | sqlite3 temp_db.sqlite3
	sqlite3 temp_db.sqlite3 "VACUUM;"
	mv temp_db.sqlite3 "$SQLITE_DB"
done
