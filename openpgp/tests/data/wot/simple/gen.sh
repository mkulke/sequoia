#! /bin/bash

set -e

if ! test -d simple
then
    echo "You're running this in the wrong directory."
    exit
fi

D=example.org
if test x$1 != "x--skip-keygen"
then
    for U in alice bob carol dave ellen frank
    do
        sq --force key generate --expires never --rev-cert /dev/null \
           --export simple/$U-priv.pgp -u "<$U@$D>"
    done
fi

{
    cd simple

    cat alice-priv.pgp
    sq certify --depth 2 --amount 100 alice-priv.pgp bob-priv.pgp "<bob@$D>"
    sq certify --depth 1 --amount 100 bob-priv.pgp carol-priv.pgp "<carol@$D>"
    sq certify --depth 1 --amount 100 carol-priv.pgp dave-priv.pgp "<dave@$D>"
    sq certify --depth 1 --amount 100 dave-priv.pgp ellen-priv.pgp "<ellen@$D>"
    # No one certifies frank.
    cat frank-priv.pgp
} | sq keyring merge > simple.pgp
