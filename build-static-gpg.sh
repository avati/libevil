#!/bin/bash -e

buildspace="/tmp/build-static-gpg";
gnupg_version="gnupg-1.4.11"
url="ftp://ftp.gnupg.org/gcrypt/gnupg/$gnupg_version.tar.bz2"
url="http://ftp.heanet.ie/disk1/ftp.gnupg.org/gcrypt/gnupg/$gnupg_version.tar.bz2"

function enter_buildspace()
{
    rm -rvf $buildspace/$gnupg_version;
    mkdir -pv $buildspace;
    cd $buildspace;
}


function prepare_source()
{
    wget -c $url;
    tar -xjf $gnupg_version.tar.bz2;
    cd $gnupg_version;
}


function build_static_gpg()
{
    ./configure CFLAGS="-static";
    make --quiet;
}


function main()
{
    (enter_buildspace; prepare_source; build_static_gpg;)

    cp -v $buildspace/$gnupg_version/g10/gpgv .;
}

main "$@"
