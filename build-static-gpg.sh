#!/bin/bash -e

buildspace="/tmp/build-static-gpg";
gnupg_version="gnupg-1.4.11"
url="ftp://ftp.gnupg.org/gcrypt/gnupg/$gnupg_version.tar.bz2"


function enter_buildspace()
{
    rm -rvf $buildspace;
    mkdir -pv $buildspace;
    cd $buildspace;
}


function prepare_source()
{
    wget -c $url;
    tar xjf $gnupg_version.tar.bz2;
    cd $gnupg_version;
}


function build_static_gpg()
{
    ./configure --quiet CFLAGS="-static" --prefix=/opt/libevil;
    make --quiet;
    make install;
}


function main()
{
    enter_buildspace;
    prepare_source;
    build_static_gpg;
}

main "$@"
