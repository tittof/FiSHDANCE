# FiSHDANCE

This is a tcl c extension that provides an implementation of
XSalsa20 with Poly1305 MAC (taken from libsodium)

It uses a random nonce in front of every message. The overhead
for the nonce and the MAC is 40 Bytes.

Make sure you feed a good key with enough entropy (256 Bit):

    pwgen -s 1048576|xz -9ve -|wc -c

    796718 <- result

    echo "45*8*796718/1048576"|bc

    273 <- result (Bits of entropy)

    recommendation:
    use pwgen -ns1 45 to get a good password because we just hash it
    down to crypto_secretbox_KEYBYTES
    using crypto_generichash (blake2b) without salt.


USAGE:

    % load ./libfishdance.so
    % ::fishdance::encrypt YoZw0ssp8bQUDhACIlYPXyeom5cIjl1pzmFWXbFdtN969 x
    AIa1dGBuCItNZwiGG5XmdbvWJhE9lcq6wldkH/5MyeHasGzdMimW0Tw=
    % ::fishdance::decrypt YoZw0ssp8bQUDhACIlYPXyeom5cIjl1pzmFWXbFdtN969 AIa1dGBuCItNZwiGG5XmdbvWJhE9lcq6wldkH/5MyeHasGzdMimW0Tw=
    x
    %
