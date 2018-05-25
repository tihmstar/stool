AM_CFLAGS = -I$(top_srcdir)/external/offsetfinder/offsetfinder/patchfinder32/

lib_LIBRARIES = patchfinder32.a
patchfinder32_a_CFLAGS = $(AM_CFLAGS)
patchfinder32_a_SOURCES = $(top_srcdir)/external/offsetfinder/offsetfinder/patchfinder32/patchfinder32.c

bin_PROGRAMS    = stool
stool_CFLAGS = $(AM_CFLAGS)
stool_LDADD = $(AM_LDFLAGS) patchfinder32.a
stool_SOURCES = main.c stool.c
