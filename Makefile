CPPFLAGS = -D_POSIX_C_SOURCE=200809L
CFLAGS = -std=c99 -pedantic -Wall -Wextra -Wvla -Werror
BIN = src/main
TARGET = dprkeygen

all: $(BIN)
	mv $(BIN) $(TARGET)

clean:
	$(RM) $(BIN) $(TARGET)
