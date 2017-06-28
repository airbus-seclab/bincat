COVERAGE=medium
PYTESTFLAGS=

test: eggloader_x86 eggloader_armv8
	python -m pytest --tb=line --coverage $(COVERAGE) $(PYTESTFLAGS)

eggloader_x86: eggloader_x86.c
	gcc -m32 -g -o $@ $<

eggloader_armv8: eggloader_armv8.c
	aarch64-linux-gnu-gcc-4.9 -static -g -o $@ $<

