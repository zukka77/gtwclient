#!/bin/bash

BASE_DIR=$(dirname $0)
BOOTSTRAP_ITALIA_URL=https://github.com/italia/bootstrap-italia/releases/latest/download/bootstrap-italia.zip
BOOTSTRAP_ITALIA_TMP=$(mktemp ${TMP:-/tmp}/XXXXXX --suffix=bootstrapitalia.zip)
BOOTSTRAP_DEST_DIR=$BASE_DIR/../client/static/client/bootstrap-italia/

curl -L ${BOOTSTRAP_ITALIA_URL} > ${BOOTSTRAP_ITALIA_TMP}
RES=$?
if [ $RES -neq 0 ];then
    echo "Error downloadin bootstrap italia"
    exit 1
fi

#SAFEGUARD, some.., sort of... 
if [[ "$BOOTSTRAP_DEST_DIR" == *"bootstrap-italia"* ]]; then 
    rm -rf $BOOTSTRAP_DEST_DIR
    mkdir $BOOTSTRAP_DEST_DIR
    unzip $BOOTSTRAP_ITALIA_TMP -d $BOOTSTRAP_DEST_DIR 
fi

