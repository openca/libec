PREFIX   := /usr
CXXFLAGS := -Iinclude -I$(PREFIX)/include -pthread
LIBS_DIR := -L$(PREFIX)/lib64
LIBS     := -lcrypto -lssl -lz -pthread -ldl

VALGRIND := \
  valgrind -v \
  --leak-check=full \
  --gen-suppressions=yes \
  --suppressions=.valgrind.supp \
  --show-reachable=yes \
  --track-origins=yes \
  --log-file=valgrind.log

SRCS := \
  libec.c  \
  t/main.c \
  t/time.c

EXE  := lib-test

all:
	@gcc -m64 -ggdb -o $(EXE) $(CXXFLAGS) $(LIBS_DIR) $(SRCS) $(LIBS)

clean:
	@rm -rf $(EXE) output/ $(EXE).dSYM *.log

run:
	@LD_LIBRARY_PATH=$(PREFIX)/lib64 $(DEBUGGER) ./$(EXE) > $(EXE).log

run-memory:
	@$(MAKE) run DEBUGGER="$(VALGRIND)"

