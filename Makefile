LDLIBS=-lpcap

all: send-arp-test

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o myAddr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

myAddr.o : myAddr.cpp mac.h ip.h
	g++ -c -o myAddr.o myAddr.cpp $(LDLIBS) 

clean:
	rm -f send-arp-test *.o
