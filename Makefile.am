ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = v49d2.la

v49d2_la_SOURCES = packet-v49d2.c plugin.c moduleinfo.h
v49d2_la_LDFLAGS = -module -avoid-version
v49d2_la_CPPFLAGS = $(WIRESHARK_CFLAGS) -I $(builddir)
v49d2_la_CFLAGS = -Wall
v49d2_la_LIBADD = $(WIRESHARK_LIBS)

# Remove the .la file, leaving just the .so
install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
