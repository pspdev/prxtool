ACLOCAL_AMFLAGS = -I aclocal
ACLOCAL_FILES = aclocal/version.m4
AM_CFLAGS = -Wall

bin_PROGRAMS = prxtool

INLCUDES = -I $(srcdir) -I $(top_srcdir)/tinyxml

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
	tinyxml/tinyxml.cpp \
	tinyxml/tinyxmlparser.cpp \
	tinyxml/tinystr.cpp \
	tinyxml/tinyxmlerror.cpp
