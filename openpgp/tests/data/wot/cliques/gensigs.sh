#! /bin/bash

set -e
#set -x

certify() {
    sq certify --amount 120 --depth 100 \
       cliques/$1-priv.pgp \
       cliques/$2-priv.pgp \
       "<$2@example.org>"
}

gen_cross_product() {
    a=$1

    for i in $(seq 0 9)
    do
        for j in $(seq 0 9)
        do
            if test $i != $j
            then
                certify $a-$i $a-$j
            fi
        done
    done
}

{
    cat cliques/root-priv.pgp

    certify root a-0
    gen_cross_product "a"
    certify a-1 b-0
    gen_cross_product "b"
    certify b-1 c-0
    gen_cross_product "c"
    certify c-1 d-0
    gen_cross_product "d"
    certify d-1 e-0
    certify e-0 f-0
    certify f-0 target
} | sq keyring merge > cliques.pgp

# Add a local optima from root to a-0.
{
    cat cliques.pgp
    sq certify --amount 30 --depth 200 cliques/root-priv.pgp cliques/a-1-priv.pgp '<a-1@example.org>';
    sq certify --amount 30 --depth 255 cliques/root-priv.pgp cliques/b-0-priv.pgp '<b-0@example.org>';
} | sq keyring merge > cliques-local-optima.pgp

# Add two local optima.
{
    cat cliques.pgp
    sq certify --amount 30 --depth 200 cliques/root-priv.pgp cliques/a-1-priv.pgp '<a-1@example.org>';
    sq certify --amount 30 --depth 255 cliques/root-priv.pgp cliques/b-0-priv.pgp '<b-0@example.org>';
    sq certify --amount 30 --depth 255 cliques/b-1-priv.pgp cliques/c-1-priv.pgp '<c-1@example.org>';
} | sq keyring merge > cliques-local-optima-2.pgp
