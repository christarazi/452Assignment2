ARGS=-std=c++11

all:	cipher RSA_specific

cipher:	cipher.o DES.o RSA.o Utils.o 
	g++ $(ARGS) cipher.o DES.o RSA.o Utils.o -o cipher -lcrypto

RSA_specific:	RSA_specific.o
	g++ $(ARGS) RSA_specific.o -o RSA_specific -lcrypto

cipher.o:	cipher.cpp 
	g++ $(ARGS) -g -c cipher.cpp

DES.o:	DES.cpp 
	g++ $(ARGS) -g -c DES.cpp

RSA.o:	RSA.cpp 
	g++ $(ARGS) -g -c RSA.cpp

RSA_specific.o:	RSA_specific.cpp
	g++ $(ARGS) -g -c RSA_specific.cpp

Utils.o: Utils.cpp
	g++ $(ARGS) -g -c Utils.cpp

clean:
	rm -rf *.o cipher RSA_specific
