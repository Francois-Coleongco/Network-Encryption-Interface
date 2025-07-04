A small network encryption library using libsodium and Berkeley sockets :)

This was used in my [MEFSC](http://github.com/francois-coleongco/MEFSC) project to secure communications over the wire to prevent MiTM (Man in The Middle) attacks.

Usage:

Clone this repo.

```git clone https://github.com/Francois-Coleongco/Network-Encryption-Library.git```

copy header files into your own include directory.

```cp ./include/*.h <your include path>```

Use the interface straight away! Documentation is within the header files, but it should be pretty straightforward :)


Building:

compile the SessionEnc.cpp and encryption_utils.cpp into object files and put them in your build directory.

```cp *.o <your build dir>```

compile your program with the object files
