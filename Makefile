
TEST_SRCS:=$(shell find . -type f -name '*.cpp' | grep -v ./main.cpp)

CC=gcc-7
CPP_FLAGS:=-std=c++17 -I$(CURDIR) -Wall -Wextra -pedantic -Werror -fmax-errors=2
LINK_FLAGS:=-lm -lstdc++

OBJDIR:=build
OBJFILES:=$(patsubst %.cpp,${OBJDIR}/%.o,${TEST_SRCS})

.PHONY: example clean

example: $(OBJDIR)/main.o $(OBJDIR)/md5.o $(OBJDIR)/sha256.o
	$(CC) $(CPP_FLAGS) $(OBJDIR)/main.o $(OBJDIR)/md5.o $(OBJDIR)/sha256.o $(LINK_FLAGS) -o example

test: $(OBJFILES)
	$(CC) $(CPP_FLAGS) $(OBJFILES) $(LINK_FLAGS) -o test

$(OBJDIR)/%.o: %.cpp
	@mkdir -p "$$(dirname "$@")"
	$(CC) -x c++ $(CPP_FLAGS) -o $@ -c $<

clean:
	rm -rf build
	rm -f test
	rm -f example

