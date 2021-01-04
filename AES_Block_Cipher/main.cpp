#define _CRT_SECURE_NO_WARNINGS 
#include <iostream>
#include <ctime>
#include "zzn.h"
#include "miracl.h"

#define PT_LEN 16

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

	char mr_aes_key_128bit[16] = { 0x00 };
	char buff[PT_LEN] = { 0x00 };

	aes a_1 = { {0x00}, };

	//! aes init& aes Keyschedule
	aes_init(&a_1, MR_ECB, 16, mr_aes_key_128bit, NULL);
	Print_char(buff, PT_LEN);

	//! aes Encryption
	aes_encrypt(&a_1, buff);
	Print_char(buff, PT_LEN);

	//! aes Decryption
	aes_decrypt(&a_1, buff);
	Print_char(buff, PT_LEN);

	aes_end(&a_1);

	system("pause");
	return 0;
}


