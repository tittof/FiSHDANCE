# FiSHDANCE

This is a tcl c extension that provides an implementation of
XSalsa20 with Poly1305 MAC (taken from libsodium)

It uses a random nonce in front of every message. The overhead
for the nonce and the MAC is 40 Bytes.

Make sure you feed a good key of 32 Bytes (256 Bit)

    % load ./libfishdance.so
    % ::fishdance::encrypt SECRET_KEY "This is an example"
    oUnfcY8tiVyzOBb6Y2+uCXOb7bnljCjhv91ySE+9f8YSayJnd0MH39uGBf4dHnEv69YHVGHqwCZ5ow==
    % ::fishdance::decrypt SECRET_KEY "oUnfcY8tiVyzOBb6Y2+uCXOb7bnljCjhv91ySE+9f8YSayJnd0MH39uGBf4dHnEv69YHVGHqwCZ5ow=="
    This is an example
    %
