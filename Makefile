main:
	gcc -shared -fPIC -o libfishdance.so -DUSE_TCL_STUBS -I/usr/local/include/tcl8.6/ -I/usr/local/include/glib-2.0/ -I/usr/local/lib/glib-2.0/include/ libfishdance_tcl.c XSalsa20Poly1305.c -ltclstub86 -lsodium -lglib-2.0
