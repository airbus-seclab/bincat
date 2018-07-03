OBJS = libc.no

%.no: %.c
	@$(C2NPK) --typed-npk -o $@ $<

all: $(OBJS)

clean:
	-rm *.no
