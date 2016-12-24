dnl Check for library paths and if static-dynamic linking is
dnl supported
AC_DEFUN(AC_CHECK_OPENSSL_PATH,
[
_package=OPENSSL
_version=$1
_prefix=$2
_dirs=$3
_arch=$4
_libs="crypto ssl"

library_prefix=
library_ldflags=
library_ldadd=
library_cflags=
library_path=
library_setup=no

if ! [[ "x${_prefix}" = "x" ]] ; then

   if [[ "x${_version}" = "x" ]] ; then
	_version=0.0.0
   fi

   if [[ -d "/opt/csw/lib/pkgconfig" ]] ; then
   	export PKG_CONFIG_PATH=/opt/csw/lib/pkgconfig:$PKG_CONFIG_PATH
   fi

   if [[ -d "/usr/sfw/lib/pkgconfig" ]] ; then
   	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/sfw/lib/pkgconfig
   fi
	
   if [[ "$enable_shared" = "yes" ]] ; then
   ifdef([PKG_CHECK_MODULES],
	[
		if ! [[ x${HAS_PKGCONF} = x  ]]; then
			PKG_CHECK_MODULES( OPENSSL, openssl >= $_version, 
			[
            	AC_MSG_RESULT([ OPENSSL $_version or greater found via pkg-config])
                library_cflags=$OPENSSL_CFLAGS
                library_ldflags=$OPENSSL_LDFLAGS
                library_ldadd=$OPENSSL_LIBS
                library_prefix=$prefix

				if [[ "x$library_prefix" = "x" ]] ; then
					my_path=${library_libs#-L}
					my_path=`echo "${my_path}" | sed "s| .*||"`
					library_path=$my_path
		   		else
		   			library_path=$library_prefix/lib$_arch
		   		fi
            	library_setup=yes
			],
			[
				AC_MSG_RESULT( [good openssl not found via pkgconfig])
				library_setup=no
			])
            dnl End of PKG_CHECK macro
		fi
	],
	[
		## Skipping pkg-config macros...
		AC_MSG_RESULT( [ Skipping pkg-config macros ])
	])
	fi
fi

if [[ "$library_setup" = "no" ]] ; then
	if [[ "x${_prefix}" = "x" ]]; then
		_path=$_dirs
	else
		if [[ -d "$_prefix/lib$_arch" ]] ; then
			_path=$_prefix/lib$_arch
		else
			_path=$_prefix/lib
		fi
	fi

	_shared=0
	_static=0

	curr_arch=

	for _i in $_path; do

		AC_MSG_RESULT([OpenSSL Checking Path: $_i])

		if [[ "$library_setup" = "yes" ]] ; then
		 	break
		fi

		dnl curr_arch=$_arch

		dir=${_i%/lib}
		if ! [[ "$dir" = "$_i" ]] ; then
			curr_arch=
		else
			curr_arch=$_arch
		fi

		AC_MSG_RESULT([OpenSSL Current Arch: .............. $curr_arch])

		library_prefix=${_i%/lib${curr_arch}}
		if [[ "$library_prefix" = "$_i" ]] ; then
			library_prefix=${library_prefix%/include}
		fi
		library_includes=${library_prefix}/include/openssl/opensslv.h

		AC_MSG_RESULT([OpenSSL Library Prefix: $library_prefix])

		if ! [[ -f "$library_includes" ]] ; then
			AC_MSG_RESULT([OpenSSL Checking Path: ${library_includes} does not exists!])
			continue;
		fi;


		AC_MSG_RESULT([Searching OpenSSL Version: $library_includes]);
		ver=`grep "^ *# *define  *SHLIB_VERSION_NUMBER" $library_includes | sed 's/[#_a-zA-Z" ]//g' | sed 's|\.|0|g'`;
		my_ver=`echo $_version | sed "s|\.|0|g"`;

		AC_MSG_RESULT([Detected Version: $ver (required > $my_ver )]);

		if [[ $ver -ge $my_ver ]] ; then
			AC_MSG_RESULT([OpenSSL Version $ver: Ok.]);
			library_cflags="-I${library_prefix}/include"

			dnl if [[ -f "${library_prefix}/openssl/opensslv.h" ]] ; then
			dnl 	library_cflags="-I${library_prefix}"
			dnl else 
			dnl 	if [[ -f "${library_prefix}/include/openssl/opensslv.h" ]] ; then
			dnl 		library_cflags="-I${library_prefix}/include"
			dnl 	fi
			dnl fi
			AC_MSG_RESULT([OpenSSL CFlags: $library_cflags ($_shared)])

			dir="$library_prefix/lib${curr_arch}"

			dnl crypto_name="${dir}/libcrypto*.$shlext*"
			dnl ssl_name="${dir}/libssl*.$shlext*"
			_static=0

			AC_MSG_RESULT([OpenSSL: Looking for $crypto_name and $ssl_name])

			if [[ $_static -gt 0 ]] ; then
				ext_list="$libext";
			else
				ext_list="$shlext $shlext.* $libext";
			fi

			for ext in $ext_list ; do
				crypto_lib=`ls "${dir}/libcrypto.${ext}" | head -n 1`;
				ssl_lib=`ls "${dir}/libssl.${ext}" | head -n 1`;

				dnl crypto_lib=`find "${dir}" -name "libcrypto.${ext}" -type f -maxdepth 0 | head -n 1`;
				dnl ssl_lib=`find "${dir}" -name "libssl.${ext}" -type f -maxdepth 0 | head -n 1`;

				echo "CRYPTO => $crypto_lib";
				echo "SSL => $ssl_lib";

				if ! [[ "${crypto_lib}" = "${ssl_lib}" ]] ; then
					library_setup=yes
					library_ldflags="-L${dir}"
					if [[ "$ext_list" = "$libext" ]] ; then
						library_shared=no
						_static=1
					else
						library_shared=yes
						_static=0
					fi
					break;
				fi
			done

			if [[ "library_setup" = "yes" ]] ; then
				AC_MSG_RESULT([OpenSSL: Found Libs in ${dir} ... ${library_ldflags}])
				break;
			fi

			continue;

		else
			AC_MSG_RESULT([OpenSSL Version $ver: Too old, skipping.]);
			library_prefix=
			library_includes=
			library_setup=no
			library_shared=no
			continue;
		fi

dnl		# done
	done
fi

if ! [[ "$library_setup" = "no" ]] ; then

if test "$cross_compiling" = yes; then
	library_setup=yes
else

old_cflags=$CFLAGS
old_ldflags=$LDFLAGS
old_libs=$LIBS

export CFLAGS=$library_cflags
export LDFLAGS=$library_ldflags
export LIBS=$library_ldadd
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$library_path

dnl AC_MSG_RESULT([LD_LIBRARY_PATH=$library_path]);

AC_RUN_IFELSE( [
#include <openssl/x509.h>
int main(void) {
	X509 *x = NULL;
	return(0);
}], [ ok=1 ], [ ok=0 ])

CFLAGS=$old_cflags
LDFLAGS=$old_ldflags
LIBS=$old_libs

if [[ $ok = 0 ]] ; then
	AC_MSG_ERROR([*** ERROR::Can not configure OPENSSL library!])
	library_shared=
	library_prefix=
	library_cflags=
	library_ldflags=
	library_ldadd=
	library_libs=
	library_setup=no
else
	AC_MSG_RESULT([Library OPENSSL prefix... $library_prefix ])
	AC_MSG_RESULT([Library OPENSSL is SHARED... $library_shared ])
	AC_MSG_RESULT([Library OPENSSL C flags... $library_cflags ])
	AC_MSG_RESULT([Library OPENSSL LD flags... $library_ldflags ])
	AC_MSG_RESULT([Library OPENSSL LIBS flags ... $library_libs ])
	library_setup=yes
fi

fi # End of Cross Compiling Check

fi # End of Library Setup 

])


dnl Check for extra support libraries and options 
AC_DEFUN(AC_CHECK_C_OPTION,
[ 
old_cflags=$CFLAGS
CFLAGS="$CFLAGS $1"

AC_MSG_CHECKING([checking for $1 support]);

AC_LANG(C)
AC_RUN_IFELSE( [
#include <stdlib.h>
int main(void)
{
        return(0);
}], [ _supported=yes ], [ _supported=no])

if [[ $_supported = no ]] ; then
        AC_MSG_RESULT([not supported]);
	CFLAGS=$old_cflags
else
        AC_MSG_RESULT([yes]);
fi])


AC_DEFUN(CHECK_EC, [
ossl_prefix=$1

if [[ "$cross_compiling" = yes ]]; then
	activate_ecdsa=yes
else
	_path=${ossl_prefix%/include}
	includes=${_path}/include/openssl


	if ! [[ -f "$includes/ec.h" ]] ; then
		AC_MSG_RESULT([OpenSSL EC: Missing Support for EC ($includes/ec.h)])
		activate_ecdsa=no;
	else
		activate_ecdsa=yes;

		files="$includes/opensslconf.h $includes/opensslconf-*.h"
		for i in files ; do
			AC_MSG_RESULT([OpenSSL EC/ECDSA: Checking support in $i])
			if [[ -f "$i" ]] ; then
				if $EGREP "define OPENSSL_NO_EC" "$i" 2>&1 >/dev/null ; then
					AC_MSG_RESULT([OpenSSL EC: Support disabled in $i])
					activate_ecdsa=no
					break
				fi
				if $EGREP "define OPENSSL_NO_ECDSA" "$i" 2>&1 >/dev/null ; then
					AC_MSG_RESULT([OpenSSL ECDSA: Support disabled in $i])
					activate_ecdsa=no
					break
				fi
			fi
		done
	fi

	AC_MSG_RESULT([OpenSSL Support for EC/ECDSA: ............ $activate_ecdsa])
fi

])


AC_DEFUN(AC_OPENSSL_VERSION,
[ AC_EGREP_HEADER( [\#define\sOPENSSL_VERSION_NUMBER\s0x],
	[ $openssl_prefix/include/openssl.h ],
	[ openssl_ver="0.9.8+"], 
    	[ openssl_ver="0.9.7"]
)

if [[ $openssl_ver = "0.9.8+" ]] ; then
	AC_DEFINE(OPENSSL_VER_00908000)
else
	AC_DEFINE(OPENSSL_VER_00907000)
fi
	AC_MSG_RESULT([OpenSSL Detected Version: $openssl_ver])
])

AC_DEFUN(AC_GCC_CHECK_PRAGMA_IGNORED,
[ AC_LANG(C)
AC_RUN_IFELSE( [
#include <stdio.h>
#pragma GCC diagnostic ignored "-Wconversion"
int main(void)
{
	return(0);
}
],[ AC_DEFINE(HAVE_GCC_PRAGMA_IGNORED, 1, [GCC pragma ignored]) ], [])

])

AC_DEFUN(AC_GCC_CHECK_PRAGMA_POP,
[ 
AC_LANG(C)
AC_RUN_IFELSE( [
#include <stdio.h>
#pragma GCC diagnostic ignored "-Wconversion"
int main(void)
{
	return(0);
}
#pragma GCC diagnostic pop
], [ AC_DEFINE(HAVE_GCC_PRAGMA_POP, 1, [GCC pragma pop]) ], [])

])

