#pragma once
#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <windows.h>


#define AES128
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

#if defined(AES256) && (AES256 == 1)
	#define AES_KEYLEN 32
	#define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
	#define AES_KEYLEN 24
	#define AES_keyExpSize 208
#else
	#define AES_KEYLEN 16   // Key length in bytes
	#define AES_keyExpSize 176
#endif

const uint8_t cmd_setInp[2] = { 0x11,0x11 };
const uint8_t cmd_setKey[2] = { 0x22,0x22 };
const uint8_t cmd_getOut[2] = { 0x44,0x44 };
const int cmd_Size = sizeof(cmd_getOut) / sizeof(uint8_t);

class AES_ctx
{
	HANDLE commPort = NULL;
	bool isRemote = false;
	bool commStatus = false;
	
public:
	uint8_t roundKey[AES_keyExpSize];

	//Constructors
	AES_ctx();
	AES_ctx(uint8_t key[]);
	AES_ctx(uint8_t key[], char port[]);

	//Public functions
	void setKey(uint8_t key[]);
	void close();
	bool status();
	void ECB_encrypt(uint8_t* buf);
	void ECB_decrypt(uint8_t* buf);
	void AES_Cipher1R(uint8_t plain_text[], int txt_Size);
};

