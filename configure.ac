AC_REVISION($Revision: 1.19 $)
AC_COPYRIGHT([Copyright 2011-2017 by Massimiliano Pala and OpenCA Labs])

dnl Autoconf
AC_INIT(libec, 0.1.0, [director@openca.org], [libec])
AC_PREREQ(2.13)
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_MACRO_DIR([m4])

dnl Release Subversion (for binary packages)
RC=1
AC_SUBST(RC)

dnl Set Version Numbers
TODAY=`/bin/date +%Y%m%d`

AC_SUBST(TODAY)

mybits="32"
mybits_install=""
is_sparc="no"
is_aix="no"
my_arch=`uname -m`
if [[ "x$host" = "x" ]] ; then
	my_arch=`uname -m`
else
	my_arch=$host
fi

case "$my_arch" in
  *i686*)
    mybits="32"
    ;;
  *i386*)
    mybits="32"
    ;;
  *86_64*)
    mybits="64"
    mybits_install="64"
    ;;
  *sparc*)
    mybits="64"
    mybits_install="64"
    is_sparc="yes"
    ;;
  *aix*)
    mybits="64"
    mybits_install="64"
    is_aix="yes"
    ;;
  *powerpc*)
    mybits="64"
    mybits_install="64"
    is_aix="yes"
    ;;
  *)
    AC_MSG_ERROR([Not supported arch ($my_arch)])
    ;;
esac

if [[ "$mybits" = "64" ]] ; then
  AC_DEFINE(ENABLE_ARCH_64, 1, [Forces 64bits builds])
else
  AC_DEFINE(ENABLE_ARCH_32, 1, [Forces 32bits builds])
fi

AC_SUBST(mybits)

v=$PACKAGE_VERSION
dnl v=`cat IFACE_VERSION`

revision=`echo $v | sed -e 's|[[0-9]]\.[[0-9]]\.[[0-9]]\.||'`
v=`echo ${v%.${revision}}`

minor=`echo $v | sed -e 's|[[0-9]]\.[[0-9]].||'`
tmp=`echo $v | sed -e 's|[[0-9]]\.[[0-9]]*||'`
major=`echo ${v%.$minor} | sed -e 's|^0*||' | sed -e 's|\.||g'`

let "iface_version=$major * 10 + $minor"

# Most Recent Implemented Interface
iface_current=$iface_version

# Implementation number of the current interface
iface_revision=$iface_current

# Oldest Interface Supported
iface_oldest=0

# Range of supported interfaces (current - oldest)
let "iface_age=$iface_current - $iface_oldest"

AC_SUBST(iface_current)
AC_SUBST(iface_revision)
AC_SUBST(iface_age)
AC_SUBST(iface_version)

# Checks for header files.

dnl #### For iPhone Support we use the special gcc from Apple ###############
dnl enable_iphone_build=no

AC_ARG_ENABLE(iphone,
	AC_HELP_STRING( [--enable-iphone],
		[enable iPhone build support ( default is yes)]),
		iphone_build=$enableval, iphone_build=no )

AC_ARG_WITH(sdk,
	AC_HELP_STRING( [--with-sdk=LIBPREFIX],
			[uses the iPhone SDK (default is 5.0)]),
			sdkver=$withval, sdkver=5.0 )
AC_SUBST(sdkver)

AC_ARG_ENABLE(extra-checks,
	AC_HELP_STRING( [--enable-extra-checks=LIBPREFIX],
		[enables extra compile-time checks (GCC) (for devel only)]),
			extra_checks=$enableval, extra_checks=no )
AC_SUBST(extra_checks)

enable_rpath=yes

# Export variables to prevent autoconf to use rpl_malloc instead
# of malloc (it won't link properly otherwise!) - needed for iPhone
# build (cross compiling)
jm_cv_func_working_malloc=yes
ac_cv_func_malloc_0_nonnull=yes

if [[ "x$iphone_build" = "xyes" ]] ; then
	AC_MSG_RESULT([*** WARNING: iPhone Development Selected])
	AC_MSG_RESULT([***          Selected SDK is ${sdkver}])

	iphone_dev=/Developer/Platforms/iPhoneOS.platform/Developer
	iphone_sdk=$iphone_dev/SDKs/iPhoneOS${sdkver}.sdk
	iphone_include=$iphone_sdk/usr/include
	iphone_bin=$iphone_dev/usr/bin
	default_path=$iphone_bin
	build_os=arm-apple-iphone
	if ! [[ "$host" = "arm-apple-darwin" ]] ; then
		AC_MSG_RESULT([*** ERROR: Please add the '--host=arm-apple-darwin' option (now used '$host') *** ])
	fi

	CC=$iphone_bin/arm-apple-darwin9-gcc-4.0.1
	CC=$iphone_bin/arm-apple-darwin10-llvm-gcc-4.2
	dnl CPP=$iphone_bin/arm-apple-darwin9-g++-4.0.1
	CFLAGS="-arch armv6 -bundle -isysroot $iphone_sdk -miphoneos-version-min=2.0"
	dnl CXX=$iphone_bin/arm-apple-darwin9-g++-4.0.1
	CXX=$iphone_bin/arm-apple-darwin10-llvm-g++-4.2
	CXXFLAGS="-arch armv6 -bundle -isysroot $iphone_sdk -miphoneos-version-min=2.0 -std=c99"
	LDFLAGS="-dead_strip -framework Foundation -framework UIKit -dynamic"
	CPPFLAGS="$CFLAGS"
	enable_rpath="no"
else
	jm_cv_func_working_malloc=yes
	ac_cv_func_malloc_0_nonnull=yes
fi

AC_CANONICAL_SYSTEM

AC_PROG_LIBTOOL

AC_PROG_EGREP

CPU=`uname -p`
AC_SUBST(CPU)

AM_INIT_AUTOMAKE([subdir-objects])

myarch=

dnl Select OS specific versions of source files.
rpath_opt="-Wl,-rpath -Wl,"
rpath=
shlext=so
dnl enable_shared=yes
case "${build_os}" in
 *linux*) 
		myarch=linux
		shlext=so
		;;
 *bsd*) myarch=bsd
		shlext=so
		;;
 *iphone*)
		myarch=iphone
		shlext=dylib
		;;
 *darwin*)
		myarch=darwin
		shlext=dylib
		mybits_install=""
		;;
 *sun*) myarch=solaris
		shlext=so
		rpath_opt="-R "
		;;
 *solaris*)
		myarch=solaris
		shlext=so
		rpath_opt="-R "
		;;
 *hpux*)        myarch=hpux
		shlext=so
		;;
 *aix*)
    myarch=aix
		shlext=so
		;;
 *) AC_MSG_ERROR([Operating system ${build_os} not supported]) ;;
esac

arch_target=

case "$target" in
	i*86-*)
		arch_target=x86
		;;
	x86_64-*)
		arch_target=x86_64
		;;
	sparc*-*)
		arch_target=Sparc
		;;
	powerpc*-*)
		arch_target=PowerPC
		;;
	*sparc*solaris*)
		arch_target=Sparc
		;;
	*arm*)
		arch_target=armv6
		;;
	*)
		[ `uname -p` ] && arch_target=`uname -p` || \
			arch_target="Unknown" ;;
esac

AC_SUBST(shlext)
AC_SUBST(arch_target)
AC_SUBST(myarch)
AC_SUBST(mybits_install)

AM_CONDITIONAL(LIBEC_ARCH_LINUX, test x$myarch = xlinux)
AM_CONDITIONAL(LIBEC_ARCH_BSD, test x$myarch = xbsd)
AM_CONDITIONAL(LIBEC_ARCH_OSX, test x$myarch = xdarwin)
AM_CONDITIONAL(LIBEC_ARCH_SOLARIS, test x$myarch = xsolaris)
AM_CONDITIONAL(LIBEC_ARCH_HPUX, test x$myarch = xhpux)
AM_CONDITIONAL(LIBEC_ARCH_AIX, test x$myarch = xaix)
AM_CONDITIONAL(LIBEC_ENABLE_IPHONE, test x$enable_iphone = xyes)

if [[ "x$myarch" = "xsolaris" ]] ; then
	DIST_VERSION=`uname -r`
else
	if [[ -f "/etc/issue" ]] ; then
	   DIST_VERSION=`$EGREP -o [[0-9.]]+ /etc/issue | head -n 1`
	else
	   DIST_VERSION=`echo ${build_os} | $EGREP -o [[0-9.]]+`
	fi
fi

AC_SUBST(DIST_VERSION)

if [[ -f "/etc/issue" ]] ; then
   DIST_NAME=`head -n 1 /etc/issue | cut -f 1,1 -d ' '`
else
   DIST_NAME=`echo ${build_os} | $EGREP -o [[A-Za-z]]+`
fi

AC_SUBST(DIST_NAME)

default_path=$PATH
if [[ "x$is_sparc" = "xyes" ]] ; then
  AC_PATH_PROG(CC, CC, , $default_path)
  AC_PATH_PROG(CXX, CC, , $default_path)
fi

if [[ "x$is_aix" = "xyes" ]] ; then
  AC_PATH_PROG(CC, cc, , $default_path)
  AC_PATH_PROG(CXX, cc, , $default_path)
  arch_opt="-q"
  ar_opt="-X$mybits"
fi

AC_PATH_PROG(MAKE, make, , $default_path)
AC_PATH_PROG(AR, ar, , $default_path)
AR="$AR $ar_opt"

if [[ "x$iphone_build" = "xno" ]] ; then
	AC_MSG_RESULT([Not an iPhone Build])
	AM_PROG_CC_C_O
fi

AM_MAINTAINER_MODE

dnl Check for install program
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_AWK
AC_PROG_MAKE_SET

dnl Automatically update the libtool script if it becomes out-of-date.
AC_SUBST(LIBTOOL_DEPS)

dnl Setup dist stuff
AC_SUBST(ac_aux_dir)

AC_CHECK_LIB(c, calloc,
        [ AC_DEFINE(HAVE_CALLOC, 1, [Calloc in C library])],
        [ AC_MSG_RESULT([no calloc was found]) ]
)

if [[ "x$iphone_build" = "xno" ]] ; then
	dnl check for libraries

	AC_HEADER_STDC
	AC_HEADER_SYS_WAIT
	AC_CHECK_HEADERS([stdlib.h string.h sys/socket.h syslog.h])

	# Checks for the POSIX.1-2001 net includes
	AC_CHECK_HEADERS([sys/select.h])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero memset setenv socket strcasecmp strchr strrchr strstr])

old_cflags="$CFLAGS"

dnl check for stack protection of gcc
if [[ "$CC" = "gcc" ]] ; then
	AC_CHECK_C_OPTION(-fstack-check)
	AC_CHECK_C_OPTION(-maccumulate-outgoing-args)
	if [[ "x${extra_checks}" = "xyes" ]] ; then
		AC_CHECK_C_OPTION(-Wall)
		AC_CHECK_C_OPTION(-Wmissing-field-initializers)
		AC_CHECK_C_OPTION(-Wmissing-parameter-type)
		AC_CHECK_C_OPTION(-Wtype-limits)
		AC_CHECK_C_OPTION(-Wuninitialized)
		AC_CHECK_C_OPTION(-Wconversion)
		AC_CHECK_C_OPTION(-Werror)
		AC_CHECK_C_OPTION(-Wfatal-errors)
		AC_CHECK_C_OPTION(-Wall)
	fi

	if [[ "$DIST_NAME" = "darwin" ]] ; then
		AC_CHECK_C_OPTION(-Wno-deprecated)
		AC_CHECK_C_OPTION(-Wno-unknown-pragmas)
	fi

	AC_GCC_CHECK_PRAGMA_IGNORED
	AC_GCC_CHECK_PRAGMA_POP
fi

EXTRA_CFLAGS=$CFLAGS
CFLAGS="$old_cflags"

dnl Check for package and related programs
AC_PATH_PROG(DATE, date)
AC_PATH_PROG(CHMOD, chmod)
AC_PATH_PROG(PKGMK, pkgmk)
AC_PATH_PROG(RPM, rpm)
if test -n "${PKGMK}"
then
        PKGMK=package
else
        if test -n "${RPM}"
        then
                PKGMK=rpm
        fi
fi
AC_SUBST(PKGMK)
AC_PATH_PROG(PERL, perl)
AC_SUBST(PERL)

dnl ============================ Pthread Support =======================

AC_CHECK_LIB(pthread, pthread_create,
        [ AC_DEFINE(HAVE_LIBPTHREAD, 1, [PTHREAD Library])],
        [ AC_MSG_ERROR([pthread library is needed!]) ]
)

pthread_opts=""
AC_MSG_RESULT([Detecting pthread cflags ... ])
AC_TRY_COMPILE( [
#include <sys/types.h>
#include <pthread.h>],
[ pthread_rwlock_t rwlock=PTHREAD_RWLOCK_INITIALIZER;]
[ return (0); ],
[ pthread_rw=yes ] , 
[ pthread_rw=no ] )

if [[ x"$pthread_rw" = xno ]] ; then
	AC_MSG_RESULT([Detecting pthread cflags (2) ... ])
	AC_TRY_COMPILE([
#define _BSD_SOURCE
#define _XOPEN_SOURCE 500
#define __USE_UNIX98
#include <sys/types.h>
#include <pthread.h>] ,
[ pthread_rwlock_t rwlock=PTHREAD_RWLOCK_INITIALIZER;]
[ return (0); ],
[ pthread_rw=yes ] , [ pthread_rw=no ])

	if test x"$pthread_rw" = xyes ; then
		pthread_opts="-D_BSD_SOURCE -D_XOPEN_SOURCE=500 -D__USE_UNIX98"
	fi
fi

if [[ x"$pthread_opts" = x ]] ; then
	AC_MSG_RESULT([pthread cflags ... none])
else
	AC_MSG_RESULT([pthread cflags ... $pthread_opts])
fi

AC_SUBST(pthread_opts)

if [[ x"$pthread_rw" = xyes ]] ; then
	AC_DEFINE(HAVE_PTHREAD_RWLOCK, 1, [HAVE_PTHREAD_RWLOCK])
fi

dnl ================= enable package building specific option ================

AC_ARG_WITH( package-prefix,
   [  --with-package-prefix=DIR         installed package prefix directory],
   [ package_prefix_cnf=$withval ] , [ package_prefix_cnf= ] )

if ! [[ "x$package_prefix_cnf" = "x" ]] ; then
	package_prefix=$package_prefix_cnf
else if [[ "x$prefix" = "xNONE" ]] ; then
		prefix=/usr
		package_prefix=${prefix}
	else
		package_prefix=${prefix}
	fi
fi

AC_ARG_WITH( libdir,
   [  --with-libdir=DIR         installed package prefix directory],
   [ libdir=$withval ] , [ libdir=$prefix/lib$mybits_install ] )

AC_SUBST(package_prefix)
AC_SUBST(prefix)
AC_SUBST(libdir)

dnl =========================== Include and lib prefixes ===============

AC_ARG_WITH( lib-prefix,
  AC_HELP_STRING( [--with-lib-prefix=LIBPREFIX],
                  [sets library prefix (default is PREFIX/lib)]),
	lib_prefix=$withval, lib_prefix=${prefix}/lib${mybits_install})
AC_SUBST( lib_prefix)

dnl databases, tmp, crypto, mails
AC_ARG_WITH( include-prefix,
	AC_HELP_STRING( [--with-include-prefix=INCLUDEPREFIX],
			[sets include prefix (default is PREFIX/include)]),
			include_prefix=$withval, include_prefix=${prefix}/include)
AC_SUBST(include_prefix)

dnl ############################## BEGIN #############################
dnl                   definitions for distribution building

AC_ARG_WITH( dist-user,
	AC_HELP_STRING( [--with-dist-user=madwolf],
		[sets user for distribution building(default is madwolf)]),
			dist_user=$withval, dist_user=madwolf)
AC_SUBST( dist_user)

AC_ARG_WITH( dist-group,
	AC_HELP_STRING( [--with-dist-group=openca],
		[sets group for distribution building(default is openca)]),
			dist_group=$withval, dist_group=openca)
AC_SUBST( dist_group)

AC_ARG_ENABLE( package-build,
	AC_HELP_STRING( [--enable-package-build],
		[enable package build (default is no)]),
			package_build=$enableval, package_build=no)
AC_SUBST(package_build)

default_path=$PATH:/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin:/opt/csw/bin

dnl Check for program paths
AC_PATH_PROG( SHELL, bash, sh, $default_path)
AC_PATH_PROG( POD2MAN, pod2man,pod2man, $default_path)
AC_PATH_PROG( MKDIR, mkdir, , $default_path)
AC_PATH_PROG( SED, sed, , $default_path)
AC_PATH_PROG( GZIP, gzip, , $default_path)
AC_PATH_PROG( ZIP, gzip, , $default_path)
AC_PATH_PROG( TAR, tar, , $default_path)
AC_PATH_PROG( PWD, pwd, , $default_path)
AC_PATH_PROG( CHMOD, chmod, , $default_path)
AC_PATH_PROG( CHOWN, chown, , $default_path)
AC_PATH_PROG( CP, cp, , $default_path)
AC_PATH_PROG( ECHO, echo, , $default_path)
AC_PATH_PROG( DOXYGEN, doxygen, , $default_path)
AC_PATH_PROG( PDFLATEX, pdflatex, , $default_path)

AC_CHECK_PROG( HAS_PKGCONF, pkg-config, yes, [] , $PATH)

dnl ========================== Install Builder Path Search ===================

builder_path=$default_path:$HOME/installbuilder/bin:$HOME/installbuilder-5.4.10/bin:$HOME/installbuilder/bin/Builder.app/Contents/MacOS/

ibuilder="builder"

if [[ "x$DIST_NAME" = "xdarwin" ]] ; then
	ibuilder="installbuilder.sh"
fi
AC_PATH_PROG(INSTALL_BUILDER, $ibuilder, , $builder_path )
AC_SUBST(INSTALL_BUILDER)

dnl ######################### CRYPTO SUPPORT #############################

AC_ARG_ENABLE( openssl,
	AC_HELP_STRING( [--enable-openssl],
		[enable openssl crypto for token operations (default is yes)]),
			enableopenssl=$enableval, enableopenssl=yes )

AC_MSG_RESULT([enable_openssl: ${enableopenssl}])

dnl Defaults
openssl_cflags=
openssl_ldflags=
openssl_ldadd=
openssl_include=
openssl_setup=no
openssl_engine=
openssl_static_libs=
openssl_min_ver=1.0.0
openssl_pkg_min_ver=1.0.1

AM_CONDITIONAL(OPENSSL_PREFIX, test ! x$openssl_prefix = x )

AC_ARG_WITH( openssl-prefix,
	AC_HELP_STRING( [--with-openssl-prefix=DIR], [openssl prefix]),
	openssl_prefix=$withval, openssl_prefix= )
AC_SUBST(openssl_prefix)

AC_MSG_RESULT([with openssl-prefix     : $openssl_prefix ])

if [[ "${enableopenssl}" = "yes" ]] ; then
   if ! [[ "x${openssl_prefix}" = "x" ]]; then
      if [[ -d "$openssl_prefix/lib/$mybits" ]] ; then
        openssl_path=$openssl_prefix/lib$mybits_install
      else
        openssl_path=$openssl_prefix/lib
      fi

	  openssl_ldadd="-lcrypto -lssl"
	  openssl_ldflags=
    AC_MSG_RESULT([openssl lib dir         : $openssl_path])
   else
    AC_MSG_RESULT([openssl lib dir         : $openssl_path (default)])

	  openssl_ldadd="-lcrypto -lssl"
	  openssl_ldflags=
	  openssl_setup=yes

	  AC_MSG_RESULT([crypto package for token operations... OPENSSL])

	  AC_DEFINE(ENABLE_OPENSSL, 1, [OPENSSL])

		dnl Now see if the user specified openssl_prefix
		    if ! [[ x${HAS_PKGCONF} = x  ]]; then
		   	PKG_CHECK_MODULES( OPENSSL,openssl >= $openssl_pkg_min_ver, [
			   AC_MSG_RESULT([openssl $openssl_pkg_min_ver or greater found via pkgconfig])
			   openssl_cflags=$OPENSSL_CFLAGS
			   openssl_ldflags=$OPENSSL_LIBS
			   openssl_prefix=$prefix
			   openssl_ldadd="-lssl -lcrypto"
			   openssl_ldflags=`echo $openssl_ldflags | sed "s|-lssl||" | sed "s|-lcrypto||"`
			   openssl_setup=yes
			fi], [AC_MSG_RESULT( [good openssl not found via pkgconfig])])

	fi
		gen_dirs="/usr/lib$mybits /usr/local/lib$mybits_install /opt/lib$mybits_install /opt/local/lib$mybits_install"
		ssl_dirs="/usr/local/ssl/lib$mybits_install /usr/local/openssl/lib$mybits_install /opt/lib$mybits_install"
		solaris_dirs="/opt/csw/lib$mybits /opt/csw/lib /opt/csw /usr/sfw/lib$mylibs /usr/sfw/lib"
		darwin_dirs=""
		aix_dirs=""

		prefix_dirs="$prefix/lib$mybits_install $prefix/lib"

		dirs="$prefix_dirs $gen_dirs $ssl_dirs $solaris_dirs $darwin_dirs $aix_dirs"

		library_cflags=
		library_ldflags=
		library_ldadd=
		library_ldpath=
		library_prefix=
		library_libs=
		library_setup=
		library_shared=
		error_number=

		AC_CHECK_OPENSSL_PATH($openssl_min_ver, "$openssl_prefix", $dirs, $mybits_install)
		if [[ "x$library_setup" = "no" ]] ; then
			AC_MSG_ERROR([**** ERROR: Can not configure OPENSSL library ($error_number)!])
		fi

		AC_MSG_RESULT([OpenSSL Prefix: $openssl_prefix])

		if [[ -d "${library_prefix%/lib$mybits_install}" ]] ; then
			openssl_prefix="${library_prefix%/lib$mybits_install}"
		else
			openssl_prefix="${library_prefix%/lib}"
		fi
		openssl_cflags="$library_cflags"
		openssl_ldflags="$library_ldflags"
		openssl_ldadd="$library_ldadd"
		openssl_include="-I$library_prefix/include"

		AC_MSG_RESULT([OpenSSL Prefix: $openssl_prefix])

		if ! [[ "x$openssl_prefix" = "x" ]] ; then
			if [[ -d "${openssl_prefix}/lib$mybits_install" ]] ; then
				openssl_path="${openssl_prefix}/lib$mybits_install";
			else
				openssl_path="${openssl_prefix}/lib"
			fi

			if test ! -z "$need_dash_r" ; then
	   	     	rpath="${rpath_opt} \"${openssl_path}\" ${rpath}"
			else
	   	     	rpath="${rpath_opt}\"${openssl_path}\" ${rpath}"
			fi
			ld_lib_path="$xml2_path:$ld_lib_path"
		fi

		if [[ "${enable_shared}" = "yes" ]] ; then
			if [[ "${library_shared}" = "no" ]] ; then
				AC_MSG_ERROR([***** ERROR: no shared openssl libs found!])
			fi
		else
			openssl_static_libs="$openssl_ldflags"
		fi

	if [[ "x$openssl_ldadd" = "x" ]] ; then
		openssl_ldadd="-lcrypto -lssl"
	fi

	AC_MSG_RESULT([ OPENSSL ldflags: ................. ${openssl_ldflags}])
	AC_MSG_RESULT([ OPENSSL ldadd: ................... ${openssl_ldadd}])

	CFLAGS="${openssl_cflags}"
	LDFLAGS="${openssl_ldflags} ${openssl_ldadd} ${openssl_static_libs}"

	if [[ "$iphone_build" = "no" ]] ; then
	    AC_SEARCH_LIBS(BIO_new, "crypto", [ ] ,
		AC_MSG_ERROR([**** ERROR::OpenSSL not Configured! (do you have the devel packages?) ****]), [-L$openssl_prefix/lib ] )
	fi

	activate_ecdsa=

   	dnl check for ECDSA support
   	AC_ARG_ENABLE( ecdsa,
   	[  --enable-ecdsa         enable Elliptic Curves DSA support],
   	[ activate_ecdsa="${enableval}" ],
        [ activate_ecdsa= ] )

	if [[ "x$activate_ecdsa" = "x" ]] ; then
		CHECK_EC(${openssl_prefix})
		if [[ "$activate_ecdsa" = "yes" ]] ; then
			AC_DEFINE([ENABLE_ECDSA], 1, [ECC Support for OpenSSL])
		fi
	else 
		if [[ "$activate_ecdsa" = "no" ]] ; then
			activate_ecdsa=no
		else
			if [[ "$activate_ecdsa" = "yes" ]] ; then
				_activate=$activate_ecdsa
				CHECK_EC(${openssl_prefix})
				if ! [[ "$_activate" = "$activate_ecdsa" ]] ; then
					AC_MSG_ERROR([*** ERROR::OpenSSL in ${openssl_prefix} does not support EC/ECDSA!])
				else
					activate_ecdsa=$_activate
					AC_DEFINE([ENABLE_ECDSA], 1, [ECC Support for OpenSSL])
				fi
			else
				AC_MSG_ERROR([*** ERROR :: Wrong value for enable-ecdsa option ($activate_ecdsa)!])
			fi
		fi
	fi

	if [[ "$activate_ecdsa" = "yes" ]] ; then
		openssl_cflags="${openssl_cflags} -DENABLE_ECDSA=1"
	fi

	CFLAGS="${old_cflags}"
	LDFLAGS="${old_ldflags}"

	AC_MSG_RESULT([ OPENSSL ldflags: ................. ${openssl_ldflags}])
	AC_MSG_RESULT([ OPENSSL ldadd: ................... ${openssl_ldadd}])

	AC_SUBST(openssl_cflags)
	AC_SUBST(openssl_ldflags)
	AC_SUBST(openssl_ldadd)
	AC_SUBST(openssl_static_libs)
	AC_SUBST(openssl_prefix)

	## End of OpenSSL build settings section ##

	dnl OpenSSL Engine Support
	AC_ARG_ENABLE( openssl-engine,
	[  --enable-openssl-engine      enable openssl engine support (yes)],
	[case "${enableval}" in
	  yes)  engine=yes ;;
	  no)   engine=no ;;
	  *) AC_MSG_ERROR([bad value ${engine} for --enable-openssl-engine]) ;;
	 esac], [engine=yes])

	AC_MSG_RESULT([enable engine support   : $engine])

	if [[ "$engine" = "yes" ]] ; then
	        AC_DEFINE(HAVE_ENGINE, 1, [ENGINE])
	fi
	AM_CONDITIONAL(ENABLE_OPENSSL_ENGINE, test "${engine}" = "yes")
fi

dnl ================= OpenSSL Static LIBS (?) =========================

AM_CONDITIONAL(STATIC_COMPILE, test "x$openssl_static_libs" != "x")
AC_CONFIG_HEADER([src/libec/config.h])

AC_ARG_ENABLE(strict,
	AC_HELP_STRING( [--enable-strict],
		[enable strict compilation error warnings (default is no)]),
		strict_compile=$enableval, strict_compile=no )

dnl ========================== GENERAL COMPILE OPTIONS ===============

sys_ldadd=
sys_cflags=

if test x$myarch = xlinux ; then
  AC_DEFINE(LIBEC_TARGET_LINUX, 1, [Linux])
  sys_ldadd="-ldl -lrt"
  sys_cflags="-DLINUX"
elif test x$myarch = xbsd ; then
  AC_DEFINE(LIBEC_TARGET_BSD, 1, [BSD])
  sys_ldadd="-lc "
  sys_cflags="-DBSD"
elif test x$myarch = xdarwin ; then
  if [[ "x$iphone_build" = "xyes" ]] ; then
    AC_DEFINE(LIBEC_TARGET_IPHONE, 1, [IPHONE])
    sys_ldadd="-dead_strip -framework Foundation -framework UIKit"
    sys_cflags="-DIPHONE"
  else
    AC_DEFINE(LIBEC_TARGET_OSX, 1, [OSX])
    sys_cflags="-DMACOS"
    dnl sys_cflags="-framework CoreFoundation"
    sys_ldadd="-ll -framework Foundation"
  fi
elif test x$myarch = xsolaris ; then
  AC_DEFINE(LIBEC_TARGET_SOLARIS, 1, [Solaris])
  sys_ldadd="-ll -ldl -lnsl -lsocket -lposix4 -lresolv -lrt"
    sys_cflags="-DSOLARIS"
elif test x$myarch = xhpux ; then
  AC_DEFINE(LIBEC_TARGET_HPUX, 1, [HP-UX])
  sys_ldadd="-ll -ldl -lrt"
  sys_cflags="-DHPUX"
fi

if [[ "${mybits}" = "32" ]] ; then
  sys_cflags="-m32 ${sys_cflags}"
  sys_ldadd="-m32 ${sys_ldadd}"
fi

if [[ "${mybits}" = "64" ]] ; then
  sys_cflags="-m64 ${sys_cflags}"
  sys_ldadd="-m64 ${sys_ldadd}"
fi
if ! [[ "$strict_compile" = "no" ]] ; then
	sys_cflags="${sys_cflags} -Wall -Werror"	
fi

AC_SUBST(sys_ldadd)
AC_SUBST(sys_cflags)

libec_cflags="-I${package_prefix}/include ${openssl_cflags}"

if [[ "${enable_shared}" = "yes" ]] ; then
  libec_ldflags="-L${lib_prefix} ${openssl_ldflags} ${openssl_ldadd}"
  libec_ldadd="-lpthread"
else
  libec_ldflags="-static -L${lib_prefix} ${openssl_ldflags}"
  libec_ldadd="-lpthread ${openssl_ldadd} ${ldap_ldadd}"
fi

# Harmonize the linker directories
h_dirs="${lib_prefix} ${prefix}/lib"
for dir in $h_dirs ; do
  if ! [[ -d "${dir}${mybits_install}" ]] ; then
    libec_ldflags=`echo $libec_ldflags | sed -e "s|-L${dir}${mybits_install}||g"`
    AC_MSG_RESULT([Removed $dir from linking (non-existing dir)])
  else
    has_dir=`echo $libec_ldflags | grep "L${dir}${mybits_install} "`
    if ! [[ "x$has_dir" = "x" ]] ; then
    	AC_MSG_RESULT([Removing duplicate entries for -L${dir}${mybits_install} from libec_ldflags])
      libec_ldflags=`echo $libec_ldflags | sed -e "s|-L${dir}${mybits_install} ||g"`
      libec_ldflags="-L${dir}${mybits_install} $libec_ldflags"
    	AC_MSG_RESULT([Removed duplicate entries for -L$dir${mybits_install} from libec_ldflags])
    fi
  fi
done

# Harmonize the linker directories
c_dirs="${prefix}/include"
for dir in $c_dirs ; do
  if ! [[ -d "$dir" ]] ; then
    libec_cflags=`echo $libec_cflags | sed -e "s|-I${dir}||g"`
    AC_MSG_RESULT([Removed $dir from includes (non-existing dir)])
  else
    has_dir=`echo $libec_cflags | grep "I${dir} "`
    if ! [[ "x$has_dir" = "x" ]] ; then
      libec_cflags=`echo "$libec_cflags" | sed -e "s|-I${dir} ||g"`
      libec_cflags="-I${dir} $libec_cflags"
    	AC_MSG_RESULT([Removed duplicate entries for -I$dir from libec_cflags])
    fi
  fi
done

# Adds all the rpaths
if ! [[ "x$enable_rpath" = "xyes" ]] ; then
	rpath=""
fi

libec_ldflags="${libec_ldflags}"
AC_SUBST(rpath)

dnl External Tools
AC_SUBST(libec_cflags)
AC_SUBST(libec_ldflags)
AC_SUBST(libec_ldadd)

dnl Internal Makefile
if [[ "${enable_shared}" = "yes" ]] ; then
	my_ldadd="-lpthread ${sys_ldadd} ${openssl_ldadd}"
	my_ldflags="-L${lib_prefix} ${openssl_ldflags} ${sys_ldflags}"
	test_libs="${sys_ldflags} ${sys_ldadd}"
else
	if [[ "$iphone_build" = "no" ]] ; then
		my_ldflags="-static -L${lib_prefix} ${openssl_ldflags}"
		my_ldadd="${sys_ldadd} ${openssl_ldadd}"
		test_libs="-static ${sys_ldadd} src/.libs/libec.a"
	else
		my_ldflags="${sys_ldflags} ${openssl_ldflags}"
		my_ldadd="${sys_ldadd} ${openssl_ldadd}"
		test_libs="${sys_ldadd}"
	fi
fi

my_cflags="${EXTRA_CFLAGS} ${libec_cflags}"
my_ldflags=`echo ${my_ldflags} | sed -e "s|-lssl||g" | sed -e "s|-lcrypto||g"`

# Harmonize the linker directories
h_dirs="${lib_prefix} ${prefix}/lib"
for dir in $h_dirs ; do
  if ! [[ -d "${dir}${mybits_install}" ]] ; then
    my_ldflags=`echo $my_ldflags | sed -e "s|-L${dir}${mybits_install}||g"`
    AC_MSG_RESULT([Removed $dir from linking (non-existing dir)])
  else
    has_dir=`echo $my_ldflags | grep "L${dir}${mybits_install} "`
    if ! [[ "x$has_dir" = "x" ]] ; then
    	AC_MSG_RESULT([Removing duplicate entries for -L${dir}${mybits_install} from my_ldflags])
      my_ldflags=`echo $my_ldflags | sed -e "s|-L${dir}${mybits_install} ||g"`
      my_ldflags="-L${dir}${mybits_install} $my_ldflags"
    	AC_MSG_RESULT([Removed duplicate entries for -L${dir}${mybits_install} from my_ldflags])
    fi
    AC_MSG_RESULT([New my_ldflags: $my_ldflags])
  fi
done

# Harmonize the linker directories
c_dirs="${prefix}/include"
for dir in $c_dirs ; do
  if ! [[ -d "$dir" ]] ; then
    my_cflags=`echo $my_cflags | sed -e "s|-I${dir}||g"`
    AC_MSG_RESULT([Removed $dir from includes (non-existing dir)])
  else
    has_dir=`echo $my_cflags | grep "I${dir} "`
    if ! [[ "x$has_dir" = "x" ]] ; then
      my_cflags=`echo "$my_cflags" | sed -e "s|-I${dir} ||g"`
      my_cflags="-I${dir} $my_cflags"
    	AC_MSG_RESULT([Removed duplicate entries for -I${dir} from my_cflags])
    fi
  fi
done

AC_SUBST(my_cflags)
AC_SUBST(my_ldflags)
AC_SUBST(my_ldadd)
AC_SUBST(test_libs)
AC_SUBST(DESTDIR)

dnl =======================[ Default Config Opts ]====================

dnl Include Directory
include_dir=${prefix}/include
AC_SUBST(include_dir)

dnl ==================================================================

AC_CONFIG_FILES(
	Makefile
	src/Makefile
	src/global-vars
	src/tests/Makefile
	src/scripts/libec-config
	contrib/libec.pc
	contrib/libec-inst.xml
)

AC_OUTPUT

if [[ "$enableopenssl" = "yes" ]] ; then
echo "
OpenSSL Configuration:
----------------------

 Library ..............: OpenSSL
 Prefix ...............: $openssl_prefix
 Compiler Flags .......: $openssl_cflags"
if [[ "${enable_shared}" = "yes" ]] ; then
echo " Linker Flags .........: $openssl_ldflags"
echo " libs .................: $openssl_ldadd"
else
echo " Libs Flags (static)...: $openssl_static_libs (${enable_shared})"
fi
echo " Support for ECDSA ....: $activate_ecdsa
"
fi

echo "
Configuration for $PACKAGE $VERSION :
--------------------------------

 Architecture .........: $myarch ($mybits bits)
 Host System Type .....: $host
 Supported URLs .......: $supported_urls
 Library Version ......: v = $iface_current, r = $iface_revision, a = $iface_age
 Install lib path .....: $libdir
 Install path .........: $package_prefix
 Compiler Flags .......: $my_cflags
 Linker Flags .........: $my_ldflags $rpath
 Libs .................: $my_ldadd
"
echo "
 Package configured for: $DIST_NAME $DIST_VERSION ($arch_target)
"

echo "
 Now type 'make' to build $PACKAGE $VERSION,
 and then 'make install' for installation.
"

