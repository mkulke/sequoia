#! /bin/bash

set -e

DIR=local-optima

if ! test -d $DIR
then
    echo "You're running this in the wrong directory (expected to find subdir '$DIR')."
    exit
fi

D=example.org
if test x$1 != "x--skip-keygen"
then
   for U in alice bob carol dave ellen francis georgina henry
   do
       sq --force key generate --expires never --rev-cert /dev/null \
          --export $DIR/$U-priv.pgp -u "<$U@$D>"
   done
fi

{
    cd $DIR

    cat alice-priv.pgp

    #    <alice@example.org> certifies:
    #      <bob@example.org>: 150, 120, *
    sq certify --depth 150 --amount 120 alice-priv.pgp bob-priv.pgp "<bob@$D>"
    #    <bob@example.org> certifies:
    #      <carol@example.org>: 50, 100, *
    #      <dave@example.org>: 100, 50, *
    #      <francis@example.org>: 200, 75, *
    sq certify --depth 50 --amount 100 bob-priv.pgp carol-priv.pgp "<carol@$D>"
    sq certify --depth 100 --amount 50 bob-priv.pgp dave-priv.pgp "<dave@$D>"

    sq certify --depth 200 --amount 75 bob-priv.pgp francis-priv.pgp "<francis@$D>"

    #    <carol@example.org> certifies:
    #      <ellen@example.org>: 50, 100, *
    sq certify --depth 50 --amount 100 carol-priv.pgp ellen-priv.pgp "<ellen@$D>"

    #    <dave@example.org> certifies:
    #      <ellen@example.org>: 100, 50, *
    sq certify --depth 100 --amount 50 dave-priv.pgp ellen-priv.pgp "<ellen@$D>"

    #    <ellen@example.org> certifies:
    #      <francis@example.org>: 100, 120, *
    #      <henry@example.org>: 0, 120, *
    #      <georgina@example.org>: 0, 30, *
    sq certify --depth 100 --amount 120 ellen-priv.pgp francis-priv.pgp "<francis@$D>"
    sq certify --amount 30 ellen-priv.pgp georgina-priv.pgp "<georgina@$D>"
    sq certify ellen-priv.pgp henry-priv.pgp "<henry@$D>"
} | sq keyring merge > $DIR.pgp
