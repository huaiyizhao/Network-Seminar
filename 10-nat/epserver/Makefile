CC = gcc
CFLAGS = -g -Wall
LIBS = -lpthread -ldl -lrt

SRCS := $(wildcard $(SRC_DIR)*.c)
OBJS := $(SRCS:.c=.o)
TARGET := epserver

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJS) : %.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean: 
	rm $(SRC_DIR)*.o 

.PHONY:clean
