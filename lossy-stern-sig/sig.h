/*
 * author: Dominik Leichtle, dominik.leichtle@web.de
 * institute: Technische Universiteit Eindhoven
 * date: Wed, 2017-12-13
 */

#ifndef SIG_H
#define SIG_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

// Use the SHAKE-256 implementation from the Keccak Team, also see keccak.noekeon.org.
#include "KeccakCodePackage-master/bin/generic64/libkeccak.a.headers/SimpleFIPS202.h"
#include "KeccakCodePackage-master/bin/generic64/libkeccak.a.headers/KeccakHash.h"

/**
  * If defined, use 64-bit integers in the application of the permutation, otherwise use 32-bit integers.
  */
#define PERMUTATIONS_USE_64BIT

#ifndef NIST_API
/**
  * Function to initialize the randomness pool. Needs to be called once in the beginning of the program.
  * @return	0 if successful, -1 otherwise
  */
int rand_init();
#endif // NIST_API

/**
  * Function to access the randomness pool.
  * @param	buf		A pointer to the buffer where to write the output data.
  * @param	bufByteLen	The desired number of output bytes.
  * @pre	If NIST_API is not defined, rand_init() must have been called already.
  * @pre	At @a buf, there are at least @a bufByteLen bytes allocated.
  * @return	0 if successful, -1 otherwise
  */
int get_randomness(unsigned char* buf, size_t bufByteLen);

/**
  * A struct representing a complete parameter set.
  */
typedef struct {
	/* Code-specific parameters */

	// length of codewords (in bits)
	size_t n;
	// number of bytes necessary to store a codeword
	size_t n_in_bytes;
	// codimension of the code (in bits)
	// equal to the length of images under the application of the parity-check matrix H
	size_t r;
	// number of bytes necessary to store an element of the image space of H
	size_t r_in_bytes;
	// weight of the secret (in bits)
	size_t w;

	/* Parameters specifying seed and commitment sizes */

	// size of the seed used to generate the secret key and H (in bytes)
	size_t seedSkByteLen;
	// size of the seed used to generate the parity-check matrix H (in bytes)
	size_t seedHByteLen;
	// size of each of the initial commitments (in bytes)
	size_t commByteLen;
	// size of the seed used to generate the random vector y (in bytes)
	size_t seedYByteLen;
	// size of the seed used to generate the random permutation (in bytes)
	size_t seedPermByteLen;
	// size of the random coins used in each of the initial commitments (in bytes)
	size_t coinsCommByteLen;

	/* Protocol-specific parameters */

	// number of parallel repetitions
	size_t t;
	// (constant) signature size (in bytes)
	// this could be interpreted as the threshold for the variable-size signatures
	size_t sigByteLen;
	// size of the hash determining the complete challenge, including all rounds (in bytes)
	size_t chHashByteLen;

	// size of the secret key (in bytes)
	size_t skByteLen;
	// size of the public key (in bytes)
	size_t pkByteLen;
} Params;

/**
  * Function to initialize a parameter set.
  * These parameters guarantee 64-bit post-quantum security.
  * Note, that this function is deterministic and will always set @a p to the same state.
  * @param	p	A pointer to the parameter set to be initialized.
  * @pre	If NIST_API is not defined, rand_init() must have been called already.
  * @return	0 if successful, -1 otherwise
  */
int init_params_64pq(Params* p);

/**
  * Function to initialize a parameter set.
  * These parameters guarantee 128-bit classical security.
  * Note, that this function is deterministic and will always set @a p to the same state.
  * @param	p	A pointer to the parameter set to be initialized.
  * @pre	If NIST_API is not defined, rand_init() must have been called already.
  * @return	0 if successful, -1 otherwise
  */
int init_params_128cl(Params* p);

/**
  * Function to initialize a parameter set.
  * These parameters guarantee 96-bit post-quantum security.
  * Note, that this function is deterministic and will always set @a p to the same state.
  * @param	p	A pointer to the parameter set to be initialized.
  * @pre	If NIST_API is not defined, rand_init() must have been called already.
  * @return	0 if successful, -1 otherwise
  */
int init_params_96pq(Params* p);

/**
  * Function to initialize a parameter set.
  * These parameters guarantee 192-bit classical security.
  * Note, that this function is deterministic and will always set @a p to the same state.
  * @param	p	A pointer to the parameter set to be initialized.
  * @pre	If NIST_API is not defined, rand_init() must have been called already.
  * @return	0 if successful, -1 otherwise
  */
int init_params_192cl(Params* p);

/**
  * Function to initialize a parameter set.
  * These parameters guarantee 128-bit post-quantum security.
  * Note, that this function is deterministic and will always set @a p to the same state.
  * @param	p	A pointer to the parameter set to be initialized.
  * @pre	If NIST_API is not defined, rand_init() must have been called already.
  * @return	0 if successful, -1 otherwise
  */
int init_params_128pq(Params* p);

/**
  * Function to initialize a parameter set.
  * These parameters guarantee 256-bit classical security.
  * Note, that this function is deterministic and will always set @a p to the same state.
  * @param	p	A pointer to the parameter set to be initialized.
  * @pre	If NIST_API is not defined, rand_init() must have been called already.
  * @return	0 if successful, -1 otherwise
  */
int init_params_256cl(Params* p);

/**
  * Function to generate a key pair.
  * @param	p	A pointer to a parameter set.
  * @param	sk	A pointer to a buffer where to store the secret key.
  * @param	pk	A pointer to a buffer where to store the public key.
  * @pre	If NIST_API is not defined, rand_init() must have been called already.
  * @pre	At @a sk, there are at least @a p->skByteLen bytes allocated.
  * @pre	At @a pk, there are at least @a p->pkByteLen bytes allocated.
  * @return	0 if successful, -1 otherwise
  */
int generate_keypair(const Params* p, unsigned char* sk, unsigned char* pk);

/**
  * Function to generate a signature.
  * @param	p		A pointer to a parameter set.
  * @param	sk		A pointer to the secret key to use in the signing process.
  * @param	message		A pointer to the message to be signed.
  * @param	messageByteLen	The length of the message, in bytes.
  * @param	sig		A pointer to a buffer where to store the signature.
  * @pre	If NIST_API is not defined, rand_init() must have been called already.
  * @pre	At @a sig, there are at least @a p->sigByteLen bytes allocated.
  * @return	0 if successful, -1 otherwise
  */
int sign(const Params* p, const unsigned char* sk, const unsigned char* message, size_t messageByteLen, unsigned char* sig);

/**
  * Function to verify a signature.
  * @param	p		A pointer to a parameter set.
  * @param	pk		A pointer to the public key to use in the verifying process.
  * @param	message		A pointer to the message to be signed.
  * @param	messageByteLen	The length of the message, in bytes.
  * @param	sig		A pointer to the signature.
  * @param	accept		A pointer to a bool where to store the result of the verification.
  *				For a valid signature, the final state of @a *accept will be true,
  *				false otherwise.
  * @return	0 if successful, -1 otherwise
  */
int verify(const Params* p, const unsigned char* pk, const unsigned char* message, size_t messageByteLen, const unsigned char* sig, bool* accept);

#endif // SIG_H

