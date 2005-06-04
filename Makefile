OUTPUT=prxtool
INCS=-I. -I/usr/local/include
CFLAGS=-Wall -O0 -ggdb 
OBJS=main.o ProcessElf.o NidMgr.o VirtualMem.o output.o ProcessPrx.o SerializePrx.o SerializePrxToIdc.o SerializePrxToXml.o
LDFLAGS=-L/usr/local/lib -ltinyxml
CC=gcc
CPP=g++

all: $(OUTPUT)

clean:
	rm -rf $(OUTPUT) $(OBJS)

$(OUTPUT): $(OBJS)
	$(CPP) $(CFLAGS) -o $(OUTPUT) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

%.o: %.C
	$(CPP) $(CFLAGS) $(INCS) -c -o $@ $<
