BITS 32:
	push 0x12345678
	push 0x200
	call 0x80000000
	push 0

x:
	db "%x",0

