
CC:= gcc
#CUR_SOURCE=${wildcard *.c}


INC:= -I ./mbedtls
RM:= rm
TARGER:= main

CUR_OBJS += aes.o
CUR_OBJS += aesni.o
CUR_OBJS += platform.o
CUR_OBJS += platform_util.o
CUR_OBJS += aes_interf.o
//CUR_OBJS += PTC_common.o

all:$(CUR_OBJS)
	$(CC) $^ $(INC) -o $(TARGER) -march=i486 -m32

%.o:%.c
	$(CC) -c $< -o $@ $(INC) -march=i486 -m32

clean:
	$(RM) $(CUR_OBJS) $(TARGET) 

