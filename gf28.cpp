#include "gf28.h"
//Constructors
gf28::gf28() {
	this->value = 0;
}
gf28::gf28(int arg) {
	value = (uint8_t)arg;
}
gf28::gf28(uint8_t arg) {
	value = arg;
}

//Private functions

	//Performs multipication in GF(2^8) using the Russian method.
uint8_t gf28::multiply(uint8_t  a, uint8_t  b) {
	uint8_t c = 0;
	while (a && b) {
		if (b & 1)		c ^= a; //if b is odd, then add to c
		if (a & 0x80)	a = (a << 1) ^ 0x11b; // XOR with the AES Rijndael primitive polynomial x^8 + x^4 + x^3 + x + 1
		else			a <<= 1;	// equivalent to a*2
		b >>= 1;
	}
	return c;
}

//Performs division in GF(2^8) by finding the multiplicative inverse thorugh brute force.
gf28 gf28::divide(gf28 arg0, gf28 arg1) {
	int invarg;
	for (invarg = 0; invarg < 255; invarg++) {
		gf28 c = arg1 * invarg;
		if (c == 1)
			break;

	}
	return arg0 * invarg;
}

//Performs the % operation a%b in GF(2^8).
uint8_t gf28::modulo(uint8_t  a, uint8_t  b) {
	if (b > a)
		return a;
	else {
		unsigned c = 0;
		while (msb(a) > msb(b)) {
			b = b << 1;
			c++;
		}
		for (unsigned c2 = 0; c2 < c; c2++) {
			if (msb(b) == msb(a))
				a = a ^ b;
			b = b >> 1;
		}
		return a ^ b;
	}
}

//Calculates the most significant bit value.
uint8_t gf28::msb(uint32_t  n) {
	if (n == 0)
		return 0;
	uint32_t  msb = 0;
	while (n != 0) {
		n = n / 2;
		msb++;
	}
	return (1 << msb);
}

//Public functions
	//Performs multiplication by 2 (x) in GF(2^8).
uint8_t gf28::xtime() {
	return ((value << 1) ^ (((value >> 7) & 1) ? 0x1b : 0x00));
}
//Performs multiplication by 3 (x+1) in GF(2^8).
uint8_t gf28::x1time() {
	return value ^ xtime();
}