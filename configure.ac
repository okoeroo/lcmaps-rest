# Copyright (c) Members of the EGEE Collaboration. 2004-2010.
# See http://www.eu-egee.org/partners/ for details on the copyright
# holders.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# 2009-
#    Oscar Koeroo <okoeroo@nikhef.nl>
#    Mischa Sall\'e <msalle@nikhef.nl>
#    David Groep <davidg@nikhef.nl>
#    NIKHEF Amsterdam, the Netherlands
#    <grid-mw-security@nikhef.nl>
#
# 2007-2009
#    Oscar Koeroo <okoeroo@nikhef.nl>
#    David Groep <davidg@nikhef.nl>
#    NIKHEF Amsterdam, the Netherlands
#
# 2003-2007
#    Martijn Steenbakkers <martijn@nikhef.nl>
#    Oscar Koeroo <okoeroo@nikhef.nl>
#    David Groep <davidg@nikhef.nl>
#    NIKHEF Amsterdam, the Netherlands
#
######################################################################

# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([LCMAPS REST Daemon], [0.0.1], okoeroo@gmail.com)
AC_CONFIG_MACRO_DIR([autodir])
AM_INIT_AUTOMAKE([1.6.3 subdir-objects foreign])
AC_CONFIG_SRCDIR([src/lcmapsd.h.in])

# Notices.
AC_COPYRIGHT([Copyright (c) 2011 of Oscar Koeroo
See LICENCE file for details
])
AC_REVISION([$Revision: 1.28 $])

#Environment.
WORKDIR=`pwd`
AC_SUBST(WORKDIR)

DISTBIN=$WORKDIR/../../dist
AC_SUBST(DISTBIN)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AM_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for libraries.
# dlopen library
AC_CHECK_LIB([dl], [dlopen])

AC_CHECK_LIB([crypto], [X509_get_subject_name])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([dlfcn.h malloc.h stdlib.h string.h syslog.h unistd.h utime.h values.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_UTIME_NULL
AC_CHECK_FUNCS([setenv strchr strcspn strdup strerror strncasecmp strpbrk strspn strstr strtol utime])

# Set lcmaps variables
AC_LCMAPS_INTERFACE([openssl])
if test "x$have_lcmaps_globus_interface" = "xno" ; then
    AC_MSG_FAILURE(["no LCMAPS globus interface found"])
fi

# Set compiled-in LCMAPS db file
# relative paths are taken to be relative to $sysconfdir/lcmaps
AC_ARG_WITH([lcmaps_db],
    [AC_HELP_STRING([--with-lcmaps-db=FILE],
		    [use specified FILE as lcmaps.db [default=SYSCONFDIR/lcmaps/lcmaps.db]])],
    [AS_IF([test "x$withval" = "xyes" -o "x$withval" = "xno" ],
	[AC_MSG_FAILURE([Option --with-lcmaps-db needs a filename])],
	[AS_IF([test "x`echo $withval|cut -c1`" != "x/" ],
  	    [LCMAPS_DB_FILE=$sysconfdir/lcmaps/$withval],
  	    [LCMAPS_DB_FILE=$withval])])
    ],
    [LCMAPS_DB_FILE="$sysconfdir/lcmaps/lcmaps.db"]
)

AC_MSG_RESULT([LCMAPS_DB_FILE set to $LCMAPS_DB_FILE])
AC_SUBST(LCMAPS_DB_FILE)
AC_SUBST(LCMAPS_DB_DIR, [`dirname $LCMAPS_DB_FILE`])
AC_SUBST(LCMAPS_DB_FILENAME, [`basename $LCMAPS_DB_FILE`])

dnl allow the setting of a different path suffix for the LCMAPS plug-ins
dnl Makefiles should set the plugindir to $MODULEDIR.
AC_ARG_WITH([lcmaps_moduledir_sfx],
    [AS_HELP_STRING([--with-lcmaps-moduledir-sfx=path],
		    [Specify the install location of the LCMAPS plug-ins with respect to LIBDIR [default=/lcmaps]])],
    [AS_IF([test "x`echo $withval|cut -c1`" != "x/" ],
	[LCMAPS_MODULEDIR_SFX=/$withval],
	[LCMAPS_MODULEDIR_SFX=$withval])],
    [LCMAPS_MODULEDIR_SFX='/lcmaps']
)
AC_SUBST(LCMAPS_MODULEDIR_SFX)
AC_MSG_RESULT([LCMAPS_MODULEDIR_SFX set to $LCMAPS_MODULEDIR_SFX])

dnl allow the setting of a different path for the LCMAPS plug-ins
dnl Makefiles should set the plugindir to $MODULEDIR.
AC_ARG_WITH([lcmaps_moduledir],
    [AS_HELP_STRING([--with-lcmaps-moduledir=path],
		    [Specify the absolute install location of the LCMAPS plug-ins to be set in the LCMAPS_DB_FILE [default=LIBDIR/LCMAPS_MODULEDIR_SFX]])],
    [AS_IF([test "x`echo $withval|cut -c1`" != "x/" ],
	[AC_MSG_FAILURE([Option --with-lcmaps-moduledir needs an absolute directory])],
	[AC_SUBST([LCMAPS_MODULEDIR], [$withval])])
    ],
    [AC_SUBST([LCMAPS_MODULEDIR], [${libdir}$LCMAPS_MODULEDIR_SFX])]
)
AC_MSG_RESULT([LCMAPS_MODULEDIR set to $LCMAPS_MODULEDIR])



AC_SUBST(ADD_THESE_DEFINES)

# Configuration items
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])

AC_CONFIG_HEADERS([src/lcmapsd.h])

AC_OUTPUT
