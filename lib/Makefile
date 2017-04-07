OBJS = stdio.no qemu.no

%.no: %.c
	@c2newspeak --typed-npk -o $@ $<

all: $(OBJS)

clean:
	-rm *.no
