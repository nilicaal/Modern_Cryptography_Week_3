CC = gcc

CFLAGS = -O2 -Wall -Wextra

PROG = solve
MAIN = main.c
HEADER_SOURCE = oracle.c

all: $(PROG)

$(HEADER_SOURCE:.c=.o): $(HEADER_SOURCE)

$(PROG): $(MAIN:.c=.o) $(HEADER_SOURCE:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^
	strip -s $@

clean:
	rm -f *.o $(PROG)
