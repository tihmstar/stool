AC_PREREQ([2.69])
AC_INIT([stool], m4_esyscmd([git rev-list --count HEAD | tr -d '\n']), [tihmstar@gmail.com])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([stool/all_stool.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
CFLAGS+=" -std=c11"
AC_PROG_INSTALL

CFLAGS+=" -D STOOL_VERSION_COMMIT_COUNT=\\\"$(git rev-list --count HEAD | tr -d '\n')\\\""
CFLAGS+=" -D STOOL_VERSION_COMMIT_SHA=\\\"$(git rev-parse HEAD | tr -d '\n')\\\""



# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile stool/Makefile])
AC_OUTPUT
