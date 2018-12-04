CFLAGS := -I. -O1 -fPIC
CXXFLAGS := $(CFLAGS)

OBJ := get_key_x86 get_key_x86_cpp get_key_armv7 get_key_armv7_thumb get_key_armv8 get_key_powerpc
all: $(OBJ)

get_key_x86: get_key.c sha1.c
	gcc $(CFLAGS) -m32 -o $@ $^

get_key_x64: get_key.c sha1.c
	gcc $(CFLAGS) -o $@ $^

get_key_malloc_x86: get_key_malloc.c sha1.c
	gcc $(CFLAGS) -m32 -o $@ $^

get_key_armv7: get_key.c sha1.c
	arm-linux-gnueabi-gcc $(CFLAGS) -o $@ $^

get_key_armv7_thumb: get_key_armv7_thumb.c sha1thumb.c
	arm-linux-gnueabi-gcc-5 $(CFLAGS) -o $@ $^

get_key_armv8: get_key.c sha1.c
	aarch64-linux-gnu-gcc $(CFLAGS) -std=gnu99 -o $@ $^

get_key_powerpc: get_key.c sha1.c
	powerpc-linux-gnu-gcc $(CFLAGS) -o $@ $^

get_key_x86_cpp: get_key_cpp.cpp sha1.c
	g++ $(CXXFLAGS) -m32 -o $@ $^ -L /usr/lib/gcc/i686-linux-gnu/7


clean:
	rm -f $(OBJ) sha1.o
