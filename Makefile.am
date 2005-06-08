ACLOCAL_AMFLAGS = -I aclocal
ACLOCAL_FILES = aclocal/version.m4 aclocal/ax_create_stdint_h.m4
AM_CFLAGS = -Wall

bin_PROGRAMS = prxtool

TINYXML = $(srcdir)/tinyxml
INLCUDES = -I $(srcdir) -I $(TINYXML)

prxtool_SOURCES = \
	main.C \
	ProcessElf.C \
	ProcessPrx.C \
	NidMgr.C \
	VirtualMem.C \
	output.C \
	SerializePrx.C \
	SerializePrxToIdc.C \
	SerializePrxToXml.C \
	$(TINYXML)/tinyxml.cpp \
	$(TINYXML)/tinyxmlparser.cpp \
	$(TINYXML)/tinystr.cpp \
	$(TINYXML)/tinyxmlerror.cpp

noinst_HEADERS = \
	types.h \
	elftypes.h \
	prxtypes.h \
	output.h \
	NidMgr.h \
	ProcessElf.h \
	ProcessPrx.h \
	SerializePrx.h \
	SerializePrxToIdc.h \
	SerializePrxToXml.h \
	VirtualMem.h \
	$(TINYXML)/tinystr.h \
	$(TINYXML)/tinyxml.h

noinst_SCRIPTS = bootstrap

EXTRA_DIST = \
	$(ACLOCAL_FILES) \
	$(TINYXML)/VERSION \
	$(TINYXML)/changes.txt \
	$(TINYXML)/readme.txt
