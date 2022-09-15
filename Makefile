CC=gcc
OPT=-O0
CFLAGS=$(OPT) -c -g 
LDFLAGS=  -lpcap -ljson-c
SRCS=$(wildcard *.c)
BINS=$(SRCS:%.c=%)

all: $(BINS)
$(BINS):$(BINS:%=%.o)
	${CC} $@.o -o $@  $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $<

clean:
	rm -rf $(BINS) *.o