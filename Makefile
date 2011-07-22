CC = gcc
CFLAGS = -Wall

tcpforwarder: tcpforwarder.o
	${CC} -o tcpforwarder tcpforwarder.o

clean:
	rm -f tcpforwarder *.o
