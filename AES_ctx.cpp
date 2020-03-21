#include "AES_ctx.h"
#include "AES.h"

#include "ScanChainAttack.h"
#include "simpleSerial.h"


AES_ctx::AES_ctx() {
	uint8_t nkey[AES_KEYLEN] = { 0 };
	KeyExpansion(this->roundKey, nkey);
}

AES_ctx::AES_ctx(uint8_t key[]){
	KeyExpansion(this->roundKey, key);
}

AES_ctx::AES_ctx(uint8_t key[],char port[]) {
	KeyExpansion(this->roundKey, key);

	if (port != "") {
		//Setup communication
		this->commPort = setComm(port);
		if (test_comm(commPort))
			commStatus = setup_comm(commPort);
		
		//Configure round key
		printf(commPort, (uint8_t*) cmd_setKey, cmd_Size); //OK
		std::string response = readf(commPort);
		commStatus &= printf(commPort, this->roundKey, AES_keyExpSize);  //OK
		response = readf(commPort); 

		if (commStatus)
			isRemote = true;
	}
}

void AES_ctx::AES_Cipher1R(uint8_t plain_text[], int txt_Size) {
	if (this->isRemote) {
		uint8_t* ui8_str = (uint8_t*)calloc(txt_Size, sizeof(uint8_t));
		std::string response;
		uint8_t* ui8_strtemp;

		printf(this->commPort, (uint8_t*) cmd_setInp, cmd_Size);    //OK
		response = readf(this->commPort);							//OK
		printf(this->commPort, plain_text, txt_Size);				//OK
		response = readf(this->commPort);							//OK

		ui8_strtemp = (uint8_t*) calloc(response.length(), sizeof(uint8_t));
		std::string subs = response.substr(16, 16);	//Taking the second block of 16 Bytes from the response (the others are just plain text messages)
		ui8_str = (uint8_t*) subs.c_str();
		
		for (int i = 0; i < txt_Size; i++) {
			plain_text[i] = ui8_str[i];
		}
	}
	else {
		Cipher_1R((state_t*) plain_text, this->roundKey );
	}
	return;
}

void AES_ctx::ECB_encrypt(uint8_t* buf) {
	if(isRemote)
		Cipher((state_t*)buf, this->roundKey);	 // Cipher  is done locally since is not implememnted in the FPGA
	else
		Cipher((state_t*)buf, this->roundKey);
}

void AES_ctx::ECB_decrypt(uint8_t* buf) {
	if (isRemote)
		InvCipher((state_t*)buf, this->roundKey); // Inv Cipher is done locally since is not implememnted in the FPGA
	else
		InvCipher((state_t*)buf, this->roundKey);
}

bool AES_ctx::status() {
	return commStatus;
}

void AES_ctx::close() {
	CloseHandle(commPort);
}

void AES_ctx::setKey(uint8_t key[]) {
	KeyExpansion(this->roundKey, key);
}