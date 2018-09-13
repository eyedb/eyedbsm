#!/bin/sh
#
# dbcreate.sh
#

if [ $# != 1 ]
then
  echo "usage: $0 <dbname>"
  exit 1
fi

set -e
if [ ! -d db ]; then mkdir db; fi

db=$1
eyedbsmtool database create `pwd`/db/$db.dbs 1 40000000 ${db}01.dat ${db}01 8000000 32 log

echo "DB=`pwd`/db/$db.dbs"
