# lossy-stern-sig
A proof-of-concept implementation of a post-quantum code-based signature scheme with lossy parameters.

### How to build the project

To build the project, the following tools must be installed:

* *GCC*
* *GNU make*
* *xsltproc*

To build the KCP, do

> `make keccak`

To build the cpucycles library, do

> `make cpucycles`

Now, one can compile our actual code by

> `make [TARGET]`

where the target must be one of the following:

* *release*
* *debug*
* *nist_api*: Build using the interface provided for the NIST PQC competition. This version uses randomness provided by the NIST interface.

### Dependencies

For the SHA-3 hash function and the SHAKE XOFs, we use the Keccak Code Package (https://github.com/XKCP/XKCP). We further use the cpucycles library (http://www.ecrypt.eu.org/ebats/cpucycles.html). For convenience, all code necessary to compile our project is included.

### License

The Keccak Code Package is mainly in the public domain, however, there exist some exceptions. See https://github.com/Thamik/lossy-stern-sig/blob/master/lossy-stern-sig/KeccakCodePackage-master/README.markdown for further details.

The cpucycles library is in the public domain.

All other code was written by Dominik Leichtle and is released to the public domain.
