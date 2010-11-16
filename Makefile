MAKEFLAGS=-B -s

# Optimization flags breaks 

#CFLAGS=-march=k8 -Wall -pedantic -mtune=k8 -std=gnu99 
CFLAGS=-O0 -Wall -pedantic -std=gnu99

all:
	make ping

ping:
	gcc ${CFLAGS} ping.c -o ping 
	sudo chown root:root ping 
	sudo chmod +s ping

clean:
	rm -f ping
