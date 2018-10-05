COVERAGE=medium
PYTESTFLAGS=

ARCHS=x86 armv7 armv7thumb armv8 powerpc
EXE=$(foreach n,$(ARCHS),eggloader_$(n))
ALLOBJ=libc.no $(EXE)


test: $(ALLOBJ)
	python2 -m pytest --tb=line --coverage $(COVERAGE) $(PYTESTFLAGS)

eggloader_x86: eggloader_x86.c
	gcc -m32 -g -o $@ $<

eggloader_armv7: eggloader_armv7.c
	arm-linux-gnueabi-gcc -static -g -o $@ $<
eggloader_armv7thumb: eggloader_armv7thumb.c
	arm-linux-gnueabi-gcc -static -g -o $@ $<

eggloader_armv8: eggloader_armv8.c
	aarch64-linux-gnu-gcc -static -g -o $@ $<

eggloader_powerpc: eggloader_powerpc.c
	powerpc-linux-gnu-gcc -static -g -o $@ $<

libc.no: libc.c
	c2newspeak --typed-npk -o $@ $<

clean:
	rm -f $(ALLOBJ)

.PHONY: clean
