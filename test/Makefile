COVERAGE=medium
PYTESTFLAGS=

test: eggloader_x86 eggloader_armv8 eggloader_armv7
	python -m pytest --tb=line --coverage $(COVERAGE) $(PYTESTFLAGS)

eggloader_x86: eggloader_x86.c
	gcc -m32 -g -o $@ $<

eggloader_armv7: eggloader_armv7.c
	arm-linux-gnueabi-gcc -static -g -o $@ $<

eggloader_armv8: eggloader_armv8.c
	aarch64-linux-gnu-gcc -static -g -o $@ $<

