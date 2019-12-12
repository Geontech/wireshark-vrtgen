AC_INIT(wireshark-vrtgen, 0.1.0)
AM_INIT_AUTOMAKE([nostdinc foreign])
AC_CONFIG_MACRO_DIR([m4])
LT_INIT([dlopen disable-static])

AC_PROG_CXX
AC_PROG_INSTALL

AM_PATH_WIRESHARK(1.10)

# Find the Wireshark plugin directory and set the standard variables libdir
# and pkglibdir to point to it. This lets Autotools know that the plugin
# should be treated as "exec" and not "data".
AC_MSG_CHECKING([wireshark plugin path])
libdir=`pkg-config --variable=libdir wireshark`
pkglibdir='${libdir}/wireshark/plugins/${WIRESHARK_VERSION}'
# Do a double-substitution to show the actual path
expanded_path=`eval echo $pkglibdir`
AC_MSG_RESULT([$expanded_path])
AC_SUBST([pkglibdir])

AC_CONFIG_FILES([Makefile moduleinfo.h])
AC_OUTPUT
