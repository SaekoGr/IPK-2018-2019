CC=g++
CFLAGS=-std=c++11 -Wextra
LFLAGS=-lpthread
LDFLAGS=-lrt -lpcap
all:
	$(CC) $(CFLAGS) ipk-scan.cpp -o ipk-scan $(FLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	-rm ipk-scan