INCLUDE := -I.
LIB := -lm
CFLAGS := -m32

test-i386:  test-i386.c test-i386-code16.S test-i386-vm86.S 
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $^ $(LIB)

