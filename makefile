TARGET = wspiper
LIBS = -lcrypto -lssl
CFLAGS = -Wall
SRC=$(wildcard *.c)

all: $(SRC)
	gcc -o $(TARGET) $^ $(CFLAGS) $(LIBS)