#pragma once
#include <stdint.h>
#include <vector>
#include <set>
#include "AES.h"

//AES state. 4x4 byte array.
//typedef state_t state_t;


void phex(uint8_t str[], int len);

//void phex(state_t state);

void XOR(uint8_t outArr[], uint8_t byteArr1[], uint8_t byteArr2[]);

//Generates the 176 long key from the last round key (round 10), for AES 128.
void keyReduction(uint8_t RoundKey[], const uint8_t Key[]);

// Byte level roattion to the right.
void RotWordL(uint8_t word[]);

//Applies the Byte level AES Substitution Box
void SubWord(uint8_t word[]);

//Applies the inverse Byte level AES Substitution Box
void RSubWord(uint8_t word[]);

template <typename T>
T getSetAt(std::set<T>& searchSet, unsigned int n);
