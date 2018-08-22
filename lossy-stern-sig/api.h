//
//  api.h
//
//  Created by Bassham, Lawrence E (Fed) on 9/6/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
//  Modified by Dominik Leichtle (TU/e), date: 19-12-2017
//


// This header wraps the lsfs128 implementation in the NIST API.

#ifndef api_h
#define api_h

#include <stdbool.h>
#include "sig.h"
#include "rng.h"

// Size of secret key, public key, signature
#define CRYPTO_SECRETKEYBYTES 32
#define CRYPTO_PUBLICKEYBYTES 218
#define CRYPTO_BYTES 320788

// The algorithm name
#define CRYPTO_ALGNAME "lsfs128"

Params p;

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);

int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);

#endif /* api_h */
