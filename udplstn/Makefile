CC=gcc
#CFLAGS= -DPONG -DDEBUG -DALRMTIME=15 -DPACKSPERALRM=10 -Wall -ggdb
CFLAGS= -DPONG -Wall 
OBJS=udplstn.o command.o exec.o signal.o
LDFLAGS=


udplstn:$(OBJS) udplstn.h
	$(CC) -o udplstn $(OBJS) $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(OBJS) udplstn
