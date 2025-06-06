CXX=g++
CC=gcc
C_SRCS=$(wildcard src/*/*/*.c src/*.c src/*/*/*/*.c)
CXX_SRCS=$(wildcard src/*.cc src/*/*/*.cc src/*/*/*/*.cc)
CFLAGS=-g3
CXXFLAGS=-g3
OBJS=${C_SRCS:.c=.o} ${CXX_SRCS:.cc=.o}
TARGET=packer.bin

all: ${TARGET} .PH0NY

${TARGET}: ${OBJS}
	${CXX} ${OBJS} -o ${TARGET}

%.o: %.cc
	${CXX} ${CXXFLAGS} -c $< -o $@

%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@

clean: .PH0NY
	rm -f ${OBJS}

fclean: clean .PH0NY
	rm -f ${TARGET}

re: fclean all .PH0NY

.PH0NY:
