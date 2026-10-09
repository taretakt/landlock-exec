CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
TARGET   = landlock-exec

$(TARGET): landlock-exec.c
	$(CC) $(CFLAGS) -o $@ $<

test: $(TARGET)
	tests/test.sh

clean:
	rm -f $(TARGET)

.PHONY: test clean