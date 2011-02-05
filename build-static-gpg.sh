#!/bin/bash -e

gnupg_version="gnupg-1.4.11"
url="ftp://ftp.gnupg.org/gcrypt/gnupg/$gnupg_version.tar.bz2"
url="http://ftp.heanet.ie/disk1/ftp.gnupg.org/gcrypt/gnupg/$gnupg_version.tar.bz2"

function prepare_source()
{
    wget -c $url;
    tar -xjf $gnupg_version.tar.bz2;
    cd $gnupg_version;
}


function build_static_gpg()
{
    ./configure --quiet CFLAGS="-static";
    make --quiet;
}


function main()
{
    (prepare_source; build_static_gpg;)

    cp -v $gnupg_version/g10/gpgv .;
}

main "$@"
