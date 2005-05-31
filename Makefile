OUTPUT=prxtool
CFLAGS=-Wall -O0 -ggdb
OBJS=main.o

all: $(OUTPUT)

clean:
	rm -rf $(OUTPUT) $(OBJS)

$(OUTPUT): $(OBJS)
	$(CC) $(CFLAGS) -o $(OUTPUT) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
