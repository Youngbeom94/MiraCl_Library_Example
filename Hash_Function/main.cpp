#define _CRT_SECURE_NO_WARNINGS 
#include <iostream>
#include <ctime>
#include "zzn.h"
#include "miracl.h"
#define SHA256_DIGEST 32
#define SHA384_DIGEST 48
#define SHA512_DIGEST 64

void Print_char(char* src, int len) {
	for (int cnt_i = 0; cnt_i < len; cnt_i++) {
		printf("%02X ", (unsigned char)src[cnt_i]);
	}
	printf("\n");
	return;
}

int main()
{
	Miracl precision = 100;
	miracl* mip = mirsys(5000, 160);

	sha256 psh_256 = { {0x00}, };
	sha384 psh_384 = { {0x00}, };
	sha512 psh_512 = { {0x00}, };


	char hash_256[SHA256_DIGEST] = { 0x00 };
	char hash_384[SHA384_DIGEST] = { 0x00 };
	char hash_512[SHA512_DIGEST] = { 0x00 };
	char msg[] = "Endeavor : No.1 hero!";


	//! sha init
	shs256_init(&psh_256);
	shs384_init(&psh_384);
	shs512_init(&psh_512);

	//! sha process
	for (int cnt_i = 0; msg[cnt_i] != 0; cnt_i++)
	{
		shs256_process(&psh_256, msg[cnt_i]);
		shs384_process(&psh_384, msg[cnt_i]);
		shs512_process(&psh_512, msg[cnt_i]);
	}

	//! hashing internal state
	shs256_hash(&psh_256, hash_256);
	shs384_hash(&psh_384, hash_384);
	shs512_hash(&psh_512, hash_512);

	printf("[SHA_256]\n");
	Print_char(hash_256, SHA256_DIGEST);

	printf("\n[SHA_384]\n");
	Print_char(hash_384, SHA384_DIGEST);

	printf("\n[SHA_512]\n");
	Print_char(hash_512, SHA512_DIGEST);
	system("pause");
	return 0;
}


