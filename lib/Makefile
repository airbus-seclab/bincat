OBJS = libc.no

%.no: %.c
	@c2newspeak --typed-npk -o $@ $<

all: $(OBJS)

clean:
	-rm *.no
