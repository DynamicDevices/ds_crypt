#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([ds_crypt], [1.0])
AC_CONFIG_SRCDIR([ds_crypt.c])
AC_CONFIG_HEADER([ds_crypt.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AM_PROG_LIBTOOL

# Set shared libraries
AC_DISABLE_STATIC
AC_ENABLE_SHARED

# Check for libcrypto
PKG_CHECK_MODULES(libcrypto, libcrypto)
AC_SUBST(libcrypto_CFLAGS)
AC_SUBST(libcrypto_LIBS)

# Check for libssl
PKG_CHECK_MODULES(libssl, libssl)
AC_SUBST(libssl_CFLAGS)
AC_SUBST(libssl_LIBS)

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
