# FiSHDANCE

This is a tcl c extension that provides an implementation of
XSalsa20 with Poly1305 MAC (taken from libsodium)

It uses a mostly random nonce in front of every message.

8 Bytes of the nonce are used as timestamp in milliseconds
since epoch and messages older than 10 seconds are discarded
if they were successfully decrypted to mitigate replay.

The overhead (nonce + MAC) is 40 Bytes.

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
    V0V19FsBAAAFkF1h9CfZbzNhCd/VKMo0Oc6aPRXOKRmfy1t6AaS6z6s=
    % ::fishdance::decrypt YoZw0ssp8bQUDhACIlYPXyeom5cIjl1pzmFWXbFdtN969 V0V19FsBAAAFkF1h9CfZbzNhCd/VKMo0Oc6aPRXOKRmfy1t6AaS6z6s=
    x
    % ::fishdance::decrypt YoZw0ssp8bQUDhACIlYPXyeom5cIjl1pzmFWXbFdtN969 V0V19FsBAAAFkF1h9CfZbzNhCd/VKMo0Oc6aPRXOKRmfy1t6AaS6z6s=
    message too old (0000000002486ms)
