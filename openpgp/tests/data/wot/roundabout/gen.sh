#! /bin/bash

set -e

DIR=roundabout

if ! test -d $DIR
then
    echo "You're running this in the wrong directory (expected to find subdir '$DIR')."
    exit
fi

D=example.org
if test x$1 != "x--skip-keygen"
then
    for U in alice bob carol dave elmar frank george henry isaac jenny
    do
        sq --force key generate --expires never --rev-cert /dev/null \
           --export $DIR/$U-priv.pgp -u "<$U@$D>"
    done
fi

{
    cd $DIR

    cat alice-priv.pgp
    cat jenny-priv.pgp
    #     <alice@example.org> certifies:
    #       <bob@example.org>: 100, 60, *
    #       <carol@example.org>: 6, 120, *
    sq certify --depth 100 --amount 60 alice-priv.pgp bob-priv.pgp "<bob@$D>"
    sq certify --depth 6 --amount 120 alice-priv.pgp carol-priv.pgp "<carol@$D>"
    #     <bob@example.org> certifies:
    #       <george@example.org>: 2, 120, *
    sq certify --depth 2 --amount 120 bob-priv.pgp george-priv.pgp "<george@$D>"
    #     <carol@example.org> certifies:
    #       <dave@example.org>: 5, 120, *
    sq certify --depth 5 --amount 120 carol-priv.pgp dave-priv.pgp "<dave@$D>"
    #     <dave@example.org> certifies:
    #       <elmar@example.org>: 4, 120, *
    sq certify --depth 4 --amount 120 dave-priv.pgp elmar-priv.pgp "<elmar@$D>"
    #     <elmar@example.org> certifies:
    #       <frank@example.org>: 3, 120, *
    sq certify --depth 3 --amount 120 elmar-priv.pgp frank-priv.pgp "<frank@$D>"
    #     <frank@example.org> certifies:
    #       <bob@example.org>: 2, 120, *
    sq certify --depth 2 --amount 120 frank-priv.pgp bob-priv.pgp "<bob@$D>"
    #     <george@example.org> certifies:
    #       <henry@example.org>: 1, 120, *
    sq certify --depth 1 --amount 120 george-priv.pgp henry-priv.pgp "<henry@$D>"
    #     <henry@example.org> certifies:
    #       <isaac@example.org>: 0, 120, *
    sq certify --depth 0 --amount 120 henry-priv.pgp isaac-priv.pgp "<isaac@$D>"
    #     <jenny@example.org> certifies:
    #       <elmar@example.org>: 5, 100, *
    #       <george@example.org>: 1, 100, *
    sq certify --depth 5 --amount 100 jenny-priv.pgp elmar-priv.pgp "<elmar@$D>"
    sq certify --depth 1 --amount 100 jenny-priv.pgp george-priv.pgp "<george@$D>"
} | sq keyring merge > $DIR.pgp
