AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

CFLAGS = -Wall -pedantic
include_HEADERS = ds_crypt.h

bin_PROGRAMS = ds_crypt
ds_crypt_SOURCES = ds_crypt.c
ds_crypt_LDFLAGS = @libcrypto_LIBS@ @libssl_LIBS@
