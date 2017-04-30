CC = gcc
CFLAGS += `pkg-config --cflags tcl glib-2.0 libsodium`
LDFLAGS += `pkg-config --libs tcl glib-2.0 libsodium`
main:
	$(CC) -shared -fPIC -o libfishdance.so -DUSE_TCL_STUBS $(CFLAGS) libfishdance_tcl.c XSalsa20Poly1305.c $(LDFLAGS)
clean:
	rm libfishdance.so
