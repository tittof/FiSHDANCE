main:
	gcc -shared -fPIC -o libfishdance.so -DUSE_TCL_STUBS `pkg-config --cflags tcl` `pkg-config --cflags glib-2.0` libfishdance_tcl.c XSalsa20Poly1305.c -ltclstub86 -lsodium -lglib-2.0
