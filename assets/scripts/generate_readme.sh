#!/bin/bash
set -e
BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
OUTPUT_FILE=${BASEDIR}/../../README.md

echo -n "" > ${OUTPUT_FILE}

for FILE_PATH in ${BASEDIR}/../../assets/docs/pages/*.md; do
  cat ${FILE_PATH} >> ${OUTPUT_FILE}
  echo >> ${OUTPUT_FILE}
done
