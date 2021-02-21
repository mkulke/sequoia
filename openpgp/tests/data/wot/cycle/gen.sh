#! /bin/bash

set -e

DIR=cycle

if ! test -d $DIR
then
    echo "You're running this in the wrong directory (expect $DIR)."
    exit
fi

D=example.org
if test x$1 != "x--skip-keygen"
then
    for U in alice bob carol dave ed frank
    do
        sq --force key generate --expires never --rev-cert /dev/null \
           --export $DIR/$U-priv.pgp -u "<$U@$D>"
    done
fi

{
    cd $DIR

    cat alice-priv.pgp
    sq certify --depth 3 --amount 120 alice-priv.pgp bob-priv.pgp "<bob@$D>"
    sq certify --depth 255 --amount 90 bob-priv.pgp carol-priv.pgp "<carol@$D>"
    sq certify --depth 255 --amount 60 carol-priv.pgp dave-priv.pgp "<dave@$D>"
    sq certify --depth 255 --amount 120 dave-priv.pgp bob-priv.pgp "<bob@$D>"
    sq certify --depth 1 --amount 30 dave-priv.pgp ed-priv.pgp "<ed@$D>"
    sq certify --depth 0 --amount 120 ed-priv.pgp frank-priv.pgp "<frank@$D>"
} | sq keyring merge > $DIR.pgp
