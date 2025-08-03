A small network encryption library using libsodium and Berkeley sockets :)

This was used in my [MEFSC](http://github.com/francois-coleongco/MEFSC) project to secure communications over the wire to prevent MiTM (Man in The Middle) attacks.

Usage:

Clone this repo.

```git clone https://github.com/Francois-Coleongco/Network-Encryption-Library.git```

copy header files into your own include directory.

```cp ./include/*.h <your include path>```

Use the interface straight away! Documentation is within the header files.

Send the `length`, then the `nonce`, then the encrypted `data`, as the `unwrap` expects that specific order.


Building:

Compile the SessionEnc.cpp and encryption_utils.cpp into object files and put them in your build directory.

```cp *.o <your build dir>```

Compile your program with the object files, and you're all set :)
