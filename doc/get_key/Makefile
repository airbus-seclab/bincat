CFLAGS := -I. -O1 -fPIC

OBJ := get_key_x86 get_key_armv7 get_key_armv8
all: $(OBJ)

get_key_x86: get_key.c sha1.c
	gcc $(CFLAGS) -m32 -o $@ $^

get_key_armv7: get_key.c sha1.c
	arm-linux-gnueabi-gcc $(CFLAGS) -o $@ $^

get_key_armv8: get_key.c sha1.c
	aarch64-linux-gnu-gcc $(CFLAGS) -std=gnu99 -o $@ $^

clean:
	rm -f $(OBJ) sha1.o
