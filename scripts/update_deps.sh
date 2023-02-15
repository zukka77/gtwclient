#!/bin/bash
set -e
BASE_DIR=$(dirname $0)
BOOTSTRAP_ITALIA_URL=https://github.com/italia/bootstrap-italia/releases/latest/download/bootstrap-italia.zip
BOOTSTRAP_ITALIA_TMP=$(mktemp --suffix=bootstrapitalia.zip)
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
    rm $BOOTSTRAP_ITALIA_TMP
fi

TMP_FILE=$(mktemp)
curl -L https://unpkg.com/vue/dist/vue.global.prod.js > $TMP_FILE && mv $TMP_FILE $BASE_DIR/../client/static/client/vue/vue.js
TMP_FILE=$(mktemp)
curl -L https://unpkg.com/vue/dist/vue.global.js  > $TMP_FILE && mv $TMP_FILE $BASE_DIR/../client/static/client/vue/vue.devel.js

TMP_DIR=$(mktemp -d)
git clone --depth 1 https://github.com/ministero-salute/it-fse-support.git $TMP_DIR
cp $TMP_DIR/doc/esempi/CDA/*.xml $BASE_DIR/../client/FSEgtwUtils/CDA/
rm -rf $TMP_DIR