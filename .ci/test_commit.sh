#!/usr/bin/env bash

# Test one commit if it has not been tested yet.
#
# We mark tested commits by touching a file named with the commit hash
# in the tested_commits dir.

COMMIT_DIR=tested_commits
COMMIT_SHA=$(git rev-list HEAD -1)
COMMIT_FILE=$COMMIT_DIR/$COMMIT_SHA

mkdir -p $COMMIT_DIR

echo ===; echo ===; echo ===;
git log -n 1;

if [ ! -f $COMMIT_FILE ]
then
  cargo test -p sequoia-openpgp && \
    echo $CI_JOB_URL >> $COMMIT_FILE
else
  echo $COMMIT_SHA has already been tested in this job:
  cat $COMMIT_FILE
fi
