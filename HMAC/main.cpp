#define _CRT_SECURE_NO_WARNINGS 
#include <iostream>
#include <ctime>
#include "zzn.h"
#include "miracl.h"

#define PT_LEN 16
#define SHA256_DIGEST 32
#define HMAC_INPUT_LEN 9
#define HMAC_INPUT_KEY_LEN 64
#define HMAC_DIGEST_LEN 32
#define IPAD 0x36
#define OPAD 0x5c

void Hash_Function_using_SHA_256(char* src, int src_len, char* digest)
{
	sha256 psh_256 = { {0x00}, };

	//! sha init
	shs256_init(&psh_256);

	//! sha process
	for (int cnt_i = 0; cnt_i<src_len; cnt_i++)
	{
		shs256_process(&psh_256, src[cnt_i]);

	}
	//! hashing internal state
	shs256_hash(&psh_256, digest);
}

void Hash_MAC(char* src, int src_len, char* key, int key_len, char* mac)
{
	char* K1 = NULL;
	char* K2 = NULL;
	char digest[SHA256_DIGEST] = { 0x00 };

	K1 = (char*)calloc(key_len + src_len, sizeof(char));
	K2 = (char*)calloc(key_len + SHA256_DIGEST, sizeof(char));

	for (int cnt_i = 0; cnt_i < key_len; cnt_i++)
	{
		K1[cnt_i] = key[cnt_i] ^ IPAD;
		K2[cnt_i] = key[cnt_i] ^ OPAD;
	}
	for (int cnt_i = key_len; cnt_i < key_len + src_len; cnt_i++)
	{
		K1[cnt_i] = src[cnt_i - key_len];
	}

	Hash_Function_using_SHA_256(K1, key_len + src_len, digest);

	for (int cnt_i = key_len; cnt_i < key_len + SHA256_DIGEST; cnt_i++)
	{
		K2[cnt_i] = digest[cnt_i - key_len];
	}
	Hash_Function_using_SHA_256(K2, key_len + SHA256_DIGEST, mac);

	free(K1);
	free(K2);
}


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

	char src[HMAC_INPUT_LEN] = { 'E', 'N', 'D','E','A','V','O','R' };
	char key[HMAC_INPUT_KEY_LEN] = { 0x00 };
	char mac[HMAC_DIGEST_LEN] = { 0x00 };

	Hash_MAC(src, HMAC_INPUT_LEN, key, HMAC_INPUT_KEY_LEN, mac);

	printf("[HMAC]\n");
	Print_char(mac, HMAC_DIGEST_LEN);

	system("pause");
	return 0;
}


