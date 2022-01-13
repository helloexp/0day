#!/bin/bash

BRANCH=${TRAVIS_BRANCH:-master}
VERSION=${PACKAGE_VERSION:-1.3.6rc5}

# Make sure that the necessary packages/tools are installed
yum install -y gcc make git rpm-build imake

# These are for the basic proftpd build
yum install -y gettext pkgconfig pam-devel ncurses-devel zlib-devel libacl-devel libcap-devel

# And these are for --with everything
yum install -y openldap-devel libmemcached-devel mysql-devel pcre-devel postgresql-devel openssl-devel tcp_wrappers-devel sqlite-devel geoip-devel

# Install the EPEL repo, for the Redis RPMs
yum install -y wget
wget -q -r --no-parent -A 'epel-release-*.rpm' http://dl.fedoraproject.org/pub/epel/7/x86_64/e
rpm -Uvh dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-*.rpm
yum install -y hiredis-devel

rm -fr rpm/
mkdir rpm/
cd rpm/
git clone -q -b ${BRANCH} --depth 10 https://github.com/proftpd/proftpd.git proftpd-${VERSION}
cd proftpd-${VERSION}/
./configure
make dist
cd ..
tar zcf proftpd-${VERSION}.tar.gz proftpd-${VERSION}
rpmbuild -ta proftpd-${VERSION}.tar.gz --with everything
