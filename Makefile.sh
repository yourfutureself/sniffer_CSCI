OBJECTS = sniffer.o functions.o
CFILES = sniffer.c functions.c
HEADERS = sniffer.h
BINARY = sniffer

all: $(BINARY)

$(BINARY)	: $(OBJECTS)
	gcc $ -o $@ $^

%.o	: %.c $(HEADERS)
	gcc -c -o $@ $<
	
clean:
	rm $(OBJECTS)
