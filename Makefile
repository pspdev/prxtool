OUTPUT=prxtool
TINYXML=./tinyxml
INCS=-I. -I$(TINYXML)
CFLAGS=-Wall -O0 -ggdb 
TINYXMLOBJS=$(TINYXML)/tinyxml.o $(TINYXML)/tinyxmlparser.o $(TINYXML)/tinystr.o $(TINYXML)/tinyxmlerror.o
OBJS=main.o ProcessElf.o NidMgr.o VirtualMem.o output.o ProcessPrx.o \
	 SerializePrx.o SerializePrxToIdc.o SerializePrxToXml.o
CC=gcc
CPP=g++

all: $(OUTPUT)

clean:
	rm -rf $(OUTPUT) $(OBJS) $(TINYXMLOBJS)

$(OUTPUT): $(OBJS) $(TINYXMLOBJS)
	$(CPP) $(CFLAGS) -o $(OUTPUT) $(OBJS) $(TINYXMLOBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

%.o: %.C
	$(CPP) $(CFLAGS) $(INCS) -c -o $@ $<
	
%.o: %.cpp
	$(CPP) $(CFLAGS) $(INCS) -c -o $@ $<
