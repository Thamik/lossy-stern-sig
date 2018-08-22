#include "api.h"

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
	init_params_128pq(&p);
	return generate_keypair(&p, sk, pk);
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk)
{
	*smlen = mlen + p.sigByteLen;
	memcpy(sm, m, mlen);
	return sign(&p, sk, m, mlen, sm+mlen);
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
	if (smlen < p.sigByteLen) {
		return -1;
	}
	bool accept;
	if (verify(&p, pk, sm, smlen - p.sigByteLen, sm + smlen - p.sigByteLen, &accept) != 0) {
		return -1;
	}
	if (!accept) {
		return -1;
	} else {
		*mlen = smlen - p.sigByteLen;
		memcpy(m, sm, *mlen);
		return 0;
	}
}

