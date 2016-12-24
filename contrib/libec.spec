# OpenCA RPM File
# (c) 2006-2017 by Massimiliano Pala and OpenCA Team
# OpenCA Licensed Software

# %define _unpackaged_files_terminate_build 0
# %define _missing_doc_files_terminate_build 0

# %_topdir /tmp/libpki-%{ver}-root/rpmbuild
# %_rpmtopdir %{_topdir}/%{name}
# %_builddir %{_rpmtopdir}/BUILD
# %_rpmdir %{_rpmtopdir}
# %_sourcedir %{_rpmtopdir}
# %_specdir %{_rpmtopdir}
# %_srcrpmdir %{_rpmtopdir}
# %_tmppath %{_rpmtopdir}/TMP

# %{_tmppath}/%{name}-root
# %define __find_requires %{nil}

# %define _unpackaged_files_terminate_build 0
# %define _missing_doc_files_terminate_build 0

# Basic Definitions
%define nobody    nobody
%define nogroup   nobody

# Different Specifications for different distributions
%define is_mandrake %(test -e /etc/mandrake-release && echo 1 || echo 0)
%define is_suse %(test -e /etc/SuSE-release && echo 1 || echo 0)
%define is_fedora %(test -e /etc/fedora-release && echo 1 || echo 0)
%define is_ubuntu %(test -e /usr/bin/ubuntu-bug && echo 1 || echo 0)
# %define is_centos %(echo `rpm -qf /etc/redhat-release --qf '%{name} 0' 2>/dev/null | sed -e 's@centos-release@1@' | awk {'print $1'}`)
%define is_centos  %(echo `rpm -qf /etc/redhat-release --qf '%{name} 0' 2>/dev/null | sed -e 's@centos-release@1 1@' | sed -e 's@[^ ]*@@' | awk {'print $1'}`)

%define dist redhat
%define disttag rh

%if %is_mandrake
%define dist mandrake
%define disttag mdk
%endif
%if %is_suse
%define dist suse
%define disttag suse
%endif
%if %is_fedora
%define dist fedora
%define disttag rhfc
%endif

%if %is_ubuntu
%define dist ubuntu
%define disttag ub
%define distver %(cat /etc/issue | grep -o -e '[0-9.]*' | sed -e 's/\\.//' )
%else
%if %is_centos
%define dist centos
%define disttag el
%endif
%endif

%define distver %(release="`rpm -q --queryformat='%{VERSION}' %{dist}-release 2> /dev/null | tr . : | sed s/://g`" ; if test $? != 0 ; then release="" ; fi ; echo "$release")
%define packer %(finger -lp `echo "$USER"` | head -n 1 | cut -d ' ' -f 2)

%define ver      	0.1.0
%define RELEASE 	1
%define rel     	%{?CUSTOM_RELEASE}%{!?CUSTOM_RELEASE:%RELEASE}
%define prefix   	/usr
%define mand		/usr/share/man
%define openssl_req 	0.9.8
%define openldap_req 	2.2

%define working_release %rel.%{disttag}%{distver}

%if %is_ubuntu
%define working_release %rel.ubu
%endif

Summary: OpenCA Easy Crypto Library
Name: libec
Version: %ver
# Release: %rel.%{disttag}%{distver}
Release: %{working_release}
License: OpenCA License (BSD Style)
Group: Security/PKI
Source: libec-%{ver}.tar.gz
Packager:  %packer
Vendor: OpenCA Labs
BuildRoot: /tmp/libec-%{ver}-root
URL: http://www.openca.org/projects/libec
#Docdir: %{prefix}/share
Prefix: %{prefix}
Requires: openssl >= %openssl_req

%description
OpenCA Labs' Easy to use crypto library for symmetric and asymmetric keys

%package devel
Summary: Development tools for libec applications
Group: Security/Crypto
Requires: libec >= %ver

%description devel
Includes and documentation for developing applications by using
libec.

%prep
%setup

%ifarch alpha
  ARCH_FLAGS="--host=alpha-redhat-linux"
%endif

if [ ! -f configure ]; then
  CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh $ARCH_FLAGS --prefix="%{prefix}" --mandir="%{mand}"
fi

DESTDIR="$RPM_BUILD_ROOT" CFLAGS="$RPM_OPT_FLAGS" ./configure $ARCH_FLAGS --prefix="%{prefix}" --mandir="%{mand}"

%build

if [ "$SMP" != "" ]; then
  (make "MAKE=make -k -j $SMP"; exit 0)
  make
else
  make
fi

make man

%install
[ -n "$RPM_BUILD_ROOT" -a "$RPM_BUILD_ROOT" != / ] && rm -rf $RPM_BUILD_ROOT

make DESTDIR="$RPM_BUILD_ROOT" prefix="%{prefix}" mandir="$RPM_BUILD_ROOT%{mand}" install

%clean
[ -n "$RPM_BUILD_ROOT" -a "$RPM_BUILD_ROOT" != / ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)

# %doc AUTHORS COPYING ChangeLog NEWS README

%{prefix}/lib64/libec*
%{prefix}/lib64/pkgconfig/libec*

%files devel
%defattr(-, root, root)
%{prefix}/bin/libec-config
%{prefix}/include/*
%{prefix}/share/*

%post

%postun


%changelog
