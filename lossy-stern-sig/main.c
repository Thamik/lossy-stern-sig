/*
 * author: Dominik Leichtle, dominik.leichtle@web.de
 * institute: Technische Universiteit Eindhoven
 * date: Wed, 2017-12-13
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "sig.h"

// for measuring the number of cpu cycles
#include "cpucycles-20060326/cpucycles.h"

// the different security levels (with increasing strength)
//#define INIT_PARAMS init_params_64pq
//#define INIT_PARAMS init_params_128cl
#define INIT_PARAMS init_params_96pq
//#define INIT_PARAMS init_params_192cl
//#define INIT_PARAMS init_params_128pq
//#define INIT_PARAMS init_params_256cl

// number of runs
#define MEASURE_CYCLES_NRUNS 20
// length of the message (in bytes)
#define MEASURE_CYCLES_MSGBYTELEN 10

// Measures the number of cpu cycles for the key generation, signing and verification procedure.
void measure_cpucycles()
{
	printf("==================================================\n");
	printf("Measuring the number of cpu cycles on average, performing %d runs.\n", MEASURE_CYCLES_NRUNS);

	long long cycles_keygen[MEASURE_CYCLES_NRUNS];
	long long cycles_sign[MEASURE_CYCLES_NRUNS];
	long long cycles_verify[MEASURE_CYCLES_NRUNS];

	// set up parameters
	Params p;
	INIT_PARAMS(&p);

	// message
	unsigned char message[MEASURE_CYCLES_MSGBYTELEN];
	for (int i=0; i<MEASURE_CYCLES_MSGBYTELEN; i++) {
		message[i] = (unsigned char)(i%256); // fill message with something
	}
	printf("Message length: %d bytes.\n", MEASURE_CYCLES_MSGBYTELEN);

	printf("|");
	for (int i=0; i<MEASURE_CYCLES_NRUNS; i++) {
		printf("-");
	}
	printf("|\n|");
	fflush(stdout);

	for (int i=0; i<MEASURE_CYCLES_NRUNS; i++) {
		// generate keypair
		unsigned char* sk = (unsigned char*) calloc(p.skByteLen, sizeof(unsigned char));
		unsigned char* pk = (unsigned char*) calloc(p.pkByteLen, sizeof(unsigned char));
		cycles_keygen[i] = cpucycles();
		generate_keypair(&p, sk, pk);
		cycles_keygen[i] = cpucycles() - cycles_keygen[i];

		// sign
		unsigned char* sig = (unsigned char*) calloc(p.sigByteLen, sizeof(unsigned char));
		cycles_sign[i] = cpucycles();
		sign(&p, sk, message, MEASURE_CYCLES_MSGBYTELEN, sig);
		cycles_sign[i] = cpucycles() - cycles_sign[i];

		// verify
		bool accept;
		cycles_verify[i] = cpucycles();
		verify(&p, pk, message, MEASURE_CYCLES_MSGBYTELEN, sig, &accept);
		cycles_verify[i] = cpucycles() - cycles_verify[i];

		// clean up
		free(sig);
		free(sk);
		free(pk);

		printf("-");
		fflush(stdout);
	}
	printf("|\n");

	// evaluate measurements, compute the average
	long long cycles_keygen_avg = 0;
	long long cycles_sign_avg = 0;
	long long cycles_verify_avg = 0;
	for (int i=0; i<MEASURE_CYCLES_NRUNS; i++) {
		cycles_keygen_avg += cycles_keygen[i];
		cycles_sign_avg += cycles_sign[i];
		cycles_verify_avg += cycles_verify[i];
	}
	cycles_keygen_avg /= MEASURE_CYCLES_NRUNS;
	cycles_sign_avg /= MEASURE_CYCLES_NRUNS;
	cycles_verify_avg /= MEASURE_CYCLES_NRUNS;

	// print results
	printf("Measured runtimes on average:\n");
	printf("Key generation:\t %lld\t cycles\n", cycles_keygen_avg);
	printf("Signing:\t %lld\t cycles\n", cycles_sign_avg);
	printf("Verification:\t %lld\t cycles\n", cycles_verify_avg);
}

// Tests key generation, signature generation and verification for one message.
bool test_sign_verify()
{
	clock_t start_total = clock();
	clock_t start = clock();
	clock_t diff;
	printf("==================================================\n");
	printf("Set up parameters and keys...\n");

	// set up parameters and keys
	Params p;
	INIT_PARAMS(&p);
	unsigned char* sk = (unsigned char*) calloc(p.skByteLen, sizeof(unsigned char));
	unsigned char* pk = (unsigned char*) calloc(p.pkByteLen, sizeof(unsigned char));
	generate_keypair(&p, sk, pk);

	diff = clock() - start;
	int msec = diff * 1000 / CLOCKS_PER_SEC;
	printf("Time: %d s %d ms.\n", msec/1000, msec%1000);
	printf("Parameters:\n");
	printf("n = \t%lu\t(length of codewords)\n", p.n);
	printf("r = \t%lu\t(codimension of the code)\n", p.r);
	printf("w = \t%lu\t(weight of the secret)\n", p.w);
	printf("t = \t%lu\t(number of parallel repetitions)\n", p.t);

	// allocate memory for H
	unsigned char** H = calloc(p.r, sizeof(unsigned char*));
	// expand the seed to obtain H
	unsigned char* temp = calloc(p.n_in_bytes * p.r, sizeof(unsigned char));
	SHAKE256(temp, p.n_in_bytes * p.r, sk, p.seedHByteLen);
	for (int i=0; i<p.r; i++) {
		H[i] = calloc(p.n_in_bytes, sizeof(unsigned char));
		memcpy(H[i], temp+i*p.n_in_bytes, p.n_in_bytes);
		// make sure the invalid bits are zero
		H[i][(p.n_in_bytes -1)] &= (unsigned char) ((1<<(((p.n+7)%8)+1))-1); // mask the last block
	}
	free(temp);

	printf("First line of the parity-check matrix:\n");
	printf("H = ");
	for (int i=0; i<p.n; i++) {
		if (i >= 50) {
			printf("...");
			break;
		}
		printf("%d", (H[0][i/8] & (1<<(i%8)))>>(i%8));
	}
	printf("\n");

	// clean up
	for (int i=0; i<p.r; i++) {
		free(H[i]);
	}
	free(H);

	printf("Private key:\n");
	printf("e = ");
	for (int i=0; i<p.n; i++) {
		if (i >= 50) {
			printf("...");
			break;
		}
		printf("%d", (sk[i/8] & (1<<(i%8)))>>(i%8));
	}
	printf("\n");
	printf("Public key:\n");
	printf("s = ");
	for (int i=0; i<p.r; i++) {
		if (i >= 50) {
			printf("...");
			break;
		}
		printf("%d", (pk[i/8] & (1<<(i%8)))>>(i%8));
	}
	printf("\n");

	// message
	const unsigned char* message = (const unsigned char*) "hello world";
	size_t messageByteLen = 12;

	start = clock();
	printf("Signature generation...\n");

	// sign
	unsigned char* sig = (unsigned char*) calloc(p.sigByteLen, sizeof(unsigned char));
	sign(&p, sk, message, messageByteLen, sig);

	diff = clock() - start;
	msec = diff * 1000 / CLOCKS_PER_SEC;
	printf("Time: %d s %d ms.\n", msec/1000, msec%1000);
	start = clock();
	printf("Verification...\n");

	// verify
	bool accept;
	verify(&p, pk, message, messageByteLen, sig, &accept);
	if (accept) {
		printf("Signature ACCEPTED.\n");
	} else {
		printf("Signature REJECTED.\n");
	}

	diff = clock() - start;
	msec = diff * 1000 / CLOCKS_PER_SEC;
	printf("Time: %d s %d ms.\n", msec/1000, msec%1000);
	start = clock();

	// clean up
	free(sig);
	free(sk);
	free(pk);

	diff = clock() - start_total;
	msec = diff * 1000 / CLOCKS_PER_SEC;
	printf("Total time: %d s %d ms.\n", msec/1000, msec%1000);

	return accept;
}

// number of messages
#define TEST_RANDOM_MESSAGES_NMSG 20
// length of each of the messages (in bytes)
#define TEST_RANDOM_MESSAGES_MSGBYTELEN 1000

// Tests key generation, signature generation and verification for randomly generated messages.
bool test_random_messages()
{
	printf("==================================================\n");
	printf("Signing and verifying %d random messages of length %d bytes.\n", TEST_RANDOM_MESSAGES_NMSG, TEST_RANDOM_MESSAGES_MSGBYTELEN);

	// set up parameters
	Params p;
	INIT_PARAMS(&p);

	// generate keypair
	unsigned char* sk = (unsigned char*) calloc(p.skByteLen, sizeof(unsigned char));
	unsigned char* pk = (unsigned char*) calloc(p.pkByteLen, sizeof(unsigned char));
	generate_keypair(&p, sk, pk);

	// message
	unsigned char message[TEST_RANDOM_MESSAGES_MSGBYTELEN];

	printf("|");
	for (int i=0; i<TEST_RANDOM_MESSAGES_NMSG; i++) {
		printf("-");
	}
	printf("|\n|");
	fflush(stdout);

	int invalid_signatures = 0;

	for (int i=0; i<TEST_RANDOM_MESSAGES_NMSG; i++) {
		// get new random message
		get_randomness(message, TEST_RANDOM_MESSAGES_MSGBYTELEN); // fill with random data

		// sign
		unsigned char* sig = (unsigned char*) calloc(p.sigByteLen, sizeof(unsigned char));
		sign(&p, sk, message, TEST_RANDOM_MESSAGES_MSGBYTELEN, sig);

		// verify
		bool accept;
		verify(&p, pk, message, TEST_RANDOM_MESSAGES_MSGBYTELEN, sig, &accept);
		if (accept) {
			// check passed successfully
		} else {
			// the signature did not verify
			invalid_signatures++;
		}

		// clean up
		free(sig);

		printf("-");
		fflush(stdout);
	}
	printf("|\n");

	// clean up
	free(sk);
	free(pk);

	// print results
	printf("Of %d messages, %d (%.1f%%) were signed and verified successfully and there were %d (%.1f%%) errors.\n", TEST_RANDOM_MESSAGES_NMSG, TEST_RANDOM_MESSAGES_NMSG-invalid_signatures, ((float)(TEST_RANDOM_MESSAGES_NMSG-invalid_signatures))*100/TEST_RANDOM_MESSAGES_NMSG, invalid_signatures, ((float)invalid_signatures)*100/TEST_RANDOM_MESSAGES_NMSG);

	return invalid_signatures == 0;
}

// number of messages
#define TEST_CORRUPTED_KEY_NMSG 20
// length of each of the messages (in bytes)
#define TEST_CORRUPTED_KEY_MSGBYTELEN 1000

// Randomly generates messages, signs them with a corrupted secret key, and tries to verify the signatures.
bool test_corrupted_key()
{
	printf("==================================================\n");
	printf("Corrupted key\n");
	printf("Signing and verifying %d random messages of length %d bytes.\n", TEST_CORRUPTED_KEY_NMSG, TEST_CORRUPTED_KEY_MSGBYTELEN);

	// set up parameters
	Params p;
	INIT_PARAMS(&p);

	// message
	unsigned char message[TEST_CORRUPTED_KEY_MSGBYTELEN];

	printf("|");
	for (int i=0; i<TEST_CORRUPTED_KEY_NMSG; i++) {
		printf("-");
	}
	printf("|\n|");
	fflush(stdout);

	int invalid_signatures = 0;

	for (int i=0; i<TEST_CORRUPTED_KEY_NMSG; i++) {
		// generate keypair
		unsigned char* sk = (unsigned char*) calloc(p.skByteLen, sizeof(unsigned char));
		unsigned char* pk = (unsigned char*) calloc(p.pkByteLen, sizeof(unsigned char));
		generate_keypair(&p, sk, pk);

		// corrupt the secret key by flipping a random bit
		// choose a random byte (this is not uniform, but will do for testing purposes)
		size_t rand_byte;
		get_randomness((unsigned char*)(&rand_byte), sizeof(size_t));
		rand_byte = rand_byte % (p.skByteLen - 1); // -1 because the last byte is "incomplete"
		// choose random bit inside this byte
		unsigned char rand_bit;
		get_randomness(&rand_bit, 1);
		rand_bit = rand_bit % 8;
		// modify secret key
		sk[rand_byte] ^= (0x01 << rand_bit);

		// get new random message
		get_randomness(message, TEST_CORRUPTED_KEY_MSGBYTELEN); // fill with random data

		// sign (with corrupted secret key)
		unsigned char* sig = (unsigned char*) calloc(p.sigByteLen, sizeof(unsigned char));
		sign(&p, sk, message, TEST_CORRUPTED_KEY_MSGBYTELEN, sig);

		// verify
		bool accept;
		verify(&p, pk, message, TEST_CORRUPTED_KEY_MSGBYTELEN, sig, &accept);
		if (accept) {
			// check passed successfully
		} else {
			// the signature did not verify
			invalid_signatures++;
		}

		// clean up
		free(sig);
		free(sk);
		free(pk);

		printf("-");
		fflush(stdout);
	}
	printf("|\n");

	// print results
	printf("Of %d messages, %d (%.1f%%) signatures with corrupted keys verified successfully and %d (%.1f%%) did not.\n", TEST_CORRUPTED_KEY_NMSG, TEST_CORRUPTED_KEY_NMSG-invalid_signatures, ((float)(TEST_CORRUPTED_KEY_NMSG-invalid_signatures))*100/TEST_CORRUPTED_KEY_NMSG, invalid_signatures, ((float)invalid_signatures)*100/TEST_CORRUPTED_KEY_NMSG);

	return invalid_signatures == TEST_CORRUPTED_KEY_NMSG;
}

// number of messages
#define TEST_CORRUPTED_MESSAGES_NMSG 20
// length of each of the messages (in bytes)
#define TEST_CORRUPTED_MESSAGES_MSGBYTELEN 1000

// Randomly generates messages, signs them, modifies the messages, and tests the verification with the corrupted messages.
bool test_corrupted_messages()
{
	printf("==================================================\n");
	printf("Corrupted messages\n");
	printf("Signing and verifying %d random messages of length %d bytes.\n", TEST_CORRUPTED_MESSAGES_NMSG, TEST_CORRUPTED_MESSAGES_MSGBYTELEN);

	// set up parameters
	Params p;
	INIT_PARAMS(&p);

	// generate keypair
	unsigned char* sk = (unsigned char*) calloc(p.skByteLen, sizeof(unsigned char));
	unsigned char* pk = (unsigned char*) calloc(p.pkByteLen, sizeof(unsigned char));
	generate_keypair(&p, sk, pk);

	// message
	unsigned char message[TEST_CORRUPTED_MESSAGES_MSGBYTELEN];

	printf("|");
	for (int i=0; i<TEST_CORRUPTED_MESSAGES_NMSG; i++) {
		printf("-");
	}
	printf("|\n|");
	fflush(stdout);

	int invalid_signatures = 0;

	for (int i=0; i<TEST_CORRUPTED_MESSAGES_NMSG; i++) {
		// get new random message
		get_randomness(message, TEST_CORRUPTED_MESSAGES_MSGBYTELEN); // fill with random data

		// sign
		unsigned char* sig = (unsigned char*) calloc(p.sigByteLen, sizeof(unsigned char));
		sign(&p, sk, message, TEST_CORRUPTED_MESSAGES_MSGBYTELEN, sig);

		// corrupt the message by flipping a random bit
		// choose a random byte (this is not uniform, but will do for testing purposes)
		size_t rand_byte;
		get_randomness((unsigned char*)(&rand_byte), sizeof(size_t));
		rand_byte = rand_byte % TEST_CORRUPTED_MESSAGES_MSGBYTELEN;
		// choose random bit inside this byte
		unsigned char rand_bit;
		get_randomness(&rand_bit, 1);
		rand_bit = rand_bit % 8;
		// modify message
		message[rand_byte] ^= (0x01 << rand_bit);

		// verify
		bool accept;
		verify(&p, pk, message, TEST_CORRUPTED_MESSAGES_MSGBYTELEN, sig, &accept);
		if (accept) {
			// check passed successfully
		} else {
			// the signature did not verify
			invalid_signatures++;
		}

		// clean up
		free(sig);

		printf("-");
		fflush(stdout);
	}
	printf("|\n");

	// clean up
	free(sk);
	free(pk);

	// print results
	printf("Of %d corrupted messages, %d (%.1f%%) signatures verified successfully and %d (%.1f%%) did not.\n", TEST_CORRUPTED_MESSAGES_NMSG, TEST_CORRUPTED_MESSAGES_NMSG-invalid_signatures, ((float)(TEST_CORRUPTED_MESSAGES_NMSG-invalid_signatures))*100/TEST_CORRUPTED_MESSAGES_NMSG, invalid_signatures, ((float)invalid_signatures)*100/TEST_CORRUPTED_MESSAGES_NMSG);

	return invalid_signatures == TEST_CORRUPTED_MESSAGES_NMSG;
}

// number of messages
#define TEST_CORRUPTED_SIGNATURES_NMSG 20
// length of each of the messages (in bytes)
#define TEST_CORRUPTED_SIGNATURES_MSGBYTELEN 1000

// Randomly generates messages, signs them, modifies the signatures, and tests the verification with the corrupted signatures.
bool test_corrupted_signatures()
{
	printf("==================================================\n");
	printf("Corrupted signatures\n");
	printf("Signing and verifying %d random messages of length %d bytes.\n", TEST_CORRUPTED_SIGNATURES_NMSG, TEST_CORRUPTED_SIGNATURES_MSGBYTELEN);

	// set up parameters
	Params p;
	INIT_PARAMS(&p);

	// generate keypair
	unsigned char* sk = (unsigned char*) calloc(p.skByteLen, sizeof(unsigned char));
	unsigned char* pk = (unsigned char*) calloc(p.pkByteLen, sizeof(unsigned char));
	generate_keypair(&p, sk, pk);

	// message
	unsigned char message[TEST_CORRUPTED_SIGNATURES_MSGBYTELEN];

	printf("|");
	for (int i=0; i<TEST_CORRUPTED_SIGNATURES_NMSG; i++) {
		printf("-");
	}
	printf("|\n|");
	fflush(stdout);

	int invalid_signatures = 0;

	for (int i=0; i<TEST_CORRUPTED_SIGNATURES_NMSG; i++) {
		// get new random message
		get_randomness(message, TEST_CORRUPTED_SIGNATURES_MSGBYTELEN); // fill with random data

		// sign
		unsigned char* sig = (unsigned char*) calloc(p.sigByteLen, sizeof(unsigned char));
		sign(&p, sk, message, TEST_CORRUPTED_SIGNATURES_MSGBYTELEN, sig);

		// corrupt the signature by flipping a random bit
		// choose a random byte (this is not uniform, but will do for testing purposes)
		size_t rand_byte;
		get_randomness((unsigned char*)(&rand_byte), sizeof(size_t));
		rand_byte = rand_byte % p.sigByteLen;
		// choose random bit inside this byte
		unsigned char rand_bit;
		get_randomness(&rand_bit, 1);
		rand_bit = rand_bit % 8;
		// modify signature
		sig[rand_byte] ^= (0x01 << rand_bit);

		// verify
		bool accept;
		verify(&p, pk, message, TEST_CORRUPTED_SIGNATURES_MSGBYTELEN, sig, &accept);
		if (accept) {
			// check passed successfully
		} else {
			// the signature did not verify
			invalid_signatures++;
		}

		// clean up
		free(sig);

		printf("-");
		fflush(stdout);
	}
	printf("|\n");

	// clean up
	free(sk);
	free(pk);

	// print results
	printf("Of %d corrupted signatures, %d (%.1f%%) verified successfully and %d (%.1f%%) did not.\n", TEST_CORRUPTED_SIGNATURES_NMSG, TEST_CORRUPTED_SIGNATURES_NMSG-invalid_signatures, ((float)(TEST_CORRUPTED_SIGNATURES_NMSG-invalid_signatures))*100/TEST_CORRUPTED_SIGNATURES_NMSG, invalid_signatures, ((float)invalid_signatures)*100/TEST_CORRUPTED_SIGNATURES_NMSG);

	return invalid_signatures == TEST_CORRUPTED_SIGNATURES_NMSG;
}

int main()
{
	// init the random pool
	printf("Initializing the randomness pool... ");
	if (rand_init() == 0) {
		printf("Successful.\n");
	} else {
		printf("Unsuccessful. Abort.\n");
		return -1;
	}

	// measure the runtime
	measure_cpucycles();

	// run some tests
	bool tests_passed = true;
	tests_passed = tests_passed & test_sign_verify();
	tests_passed = tests_passed & test_random_messages();
	tests_passed = tests_passed & test_corrupted_key();
	tests_passed = tests_passed & test_corrupted_messages();
	tests_passed = tests_passed & test_corrupted_signatures();
	printf("==================================================\n");
	if (tests_passed) {
		printf("All tests PASSED.\n");
	} else {
		printf("ERRORS were detected during the tests.\n");
	}

	return 0;
}

