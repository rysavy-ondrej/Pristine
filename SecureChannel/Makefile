#=============================================================================
# Name        : Makefile
# Author      : Ondrej Rysavy
# Date        : Jan 08, 2015
# Copyright   : (c) Brno University of Technology
# Description : Makefile for SecureChannel demo.
#
#               It makes two executable: udtdemo and idtproxy.
#               sechan - Demostrates principles of a secure channel communication.
#               udtproxy - Implements UDP proxy that can drop packets, 
#                          reorded packets, and injects bit errors.
#
# Usage:        make [build] - for building the project 
#               make clean   - for cleaning the projects immediate files and
#                              executables.
#
#============================================================================
CC=gcc
CFLAGS=-c -Wall -I../Packages/include -m32
LDFLAGS=-L../Packages/lib -lcrypto -m32
SOURCES=sechan.c udtproxy.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLES=sechan udtproxy

.PHONY: build
.PHONY: clean

all: ${SOURCES} ${EXECUTABLES}
	
sechan:  $(OBJECTS) 
	${CC} ${LDFLAGS} -o sechan sechan.o

udtproxy:  $(OBJECTS) 
	${CC} ${LDFLAGS} -o udtproxy udtproxy.o

.c.o:
	${CC} ${CFLAGS} $< -o $@


clean:
	rm -f *.o *.core ${EXECUTABLES}

