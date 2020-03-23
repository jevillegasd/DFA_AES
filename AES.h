#pragma once
/*
This is an implementation of the AES algorithm, ONLY ECB mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97
    f5d3d58503b9699de785895a96fdbaaf
    43b1cd7f598ece23881b00e3ed030688
    7b0c785e27e8ad3f8223207104725dd4


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/


#ifndef _AES_H_
    #define _AES_H_

    #include <stdint.h>
    #include "AES_ctx.h"
    #include "gf28.h"
    // #define the macros below to 1/0 to enable/disable the mode of operation.
    //
    // CBC enables AES encryption in CBC-mode of operation.
    // CTR enables encryption in counter-mode.
    // ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

    #ifndef CBC
    #define CBC 1
    #endif
    #ifndef ECB
    #define ECB 1
    #endif
    #ifndef CTR
    #define CTR 1
    #endif

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


    // state - array holding the intermediate results during decryption.
    typedef uint8_t state_t[4][4];
   // This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
   void KeyExpansion(uint8_t RoundKey[], const uint8_t Key[]);

   void AES_init_ctx(AES_ctx ctx, const uint8_t key[]);
    
   void AES_ECB_encrypt( AES_ctx ctx, uint8_t* buf);

   void AES_ECB_decrypt( AES_ctx ctx, uint8_t* buf);

   void AES_Cipher_1R(AES_ctx ctx, uint8_t* buf);

   void Cipher(state_t* state, const uint8_t RoundKey[AES_keyExpSize]);
   void InvCipher(state_t* state, const uint8_t RoundKey[AES_keyExpSize]);
   void Cipher_1R(state_t* state, const uint8_t RoundKey[AES_keyExpSize]);

    #define getSBoxValue(num) (sbox[(num)]);
    #define getSBoxInvert(num) (rsbox[(num)]);

    //Sbox subsitution of one byte 
    uint8_t byte_sbox(uint8_t byte);

    //Inverse Sbox subsitution of one byte
    uint8_t byte_rsbox(uint8_t byte);

    //Inverse Sbox subsitution of one byte
    gf28 ISB(gf28 byte);

    void SubBytes(state_t* state);

    

    // MixColumns function mixes the columns of the state matrix
    void MixColumns(state_t* state);
   
    // This function adds the round key to state.
    // The round key is added to the state by an XOR function.
    static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey);
    
    static void InvAddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey);

    // The SubBytes Function Substitutes the values in the
    // state matrix with values in an S-box.
    // static void SubBytes(state_t* state);

    // The ShiftRows() function shifts the rows in the state to the left.
    // Each row is shifted with different offset.
    // Offset = Row number. So the first row is not shifted.
    void ShiftRows(state_t* state);

    void InvShiftRows(state_t* state);

    // Multiply is used to multiply numbers in the field GF(2^8)
    // Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
    //       The compiler seems to be able to vectorize the operation better this way.
    //       See https://github.com/kokke/tiny-AES-c/pull/34
    #if MULTIPLY_AS_A_FUNCTION
        {static __int8 Multiply(__int8 x, __int8 y); }
    #else {
        #define Multiply(x, y)                                \
              (  ((y & 1) * x) ^                              \
              ((y>>1 & 1) * xtime(x)) ^                       \
              ((y>>2 & 1) * xtime(xtime(x))) ^                \
              ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
              ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \
        }
    #endif

    void phex(state_t state);

    void Cipher_biterror(state_t* state, const uint8_t RoundKey[AES_keyExpSize], uint8_t byte, uint8_t err);

    uint8_t xtime(uint8_t x);
#endif //_AES_H_