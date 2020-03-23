//Variable in the finite field GF(2^8) 
//Developed by J.Villegas March 2020 (the year of the virus)
//Version 1.0.0.
//CC Commons License

#pragma once

#ifndef _GF28
#define _GF28

#include <iostream>
#include <iomanip>

//Byte 
class gf28 {
	uint8_t modulo(uint8_t  a, uint8_t  b);
	uint8_t multiply(uint8_t  a, uint8_t  b);
	gf28 divide(gf28  a, gf28  b);
	uint8_t msb(uint32_t  n);
public:
	uint8_t value;

	//Constructors
	gf28();
	gf28(int arg);
	gf28(uint8_t arg);

	//Overloaded operators
	gf28 operator + (gf28& arg1) { return value ^ arg1.value; }
	gf28 operator + (int& arg1) { return value ^ ((gf28)arg1).value; }
	gf28 operator + (const int& arg1) { return value ^ ((gf28)arg1).value; }

	gf28 operator * (gf28& arg1) { return multiply(value, arg1.value); }
	gf28 operator * (int& arg1) { return multiply(value, ((gf28)arg1).value); }
	gf28 operator * (const int& arg1) { return multiply(value, ((gf28)arg1).value); }

	gf28 operator % (gf28& arg1) { return modulo(value, arg1.value); }
	gf28 operator % (int& arg1) { return modulo(value, ((gf28)arg1).value); }
	gf28 operator % (const int& arg1) { return modulo(value, ((gf28)arg1).value); }

	gf28 operator = (uint8_t& arg1) { value = arg1; return value; }

	gf28 operator == (gf28& arg1) { return value == arg1; }

	gf28 operator / (gf28& arg1) { return divide(*this, arg1); }

	friend std::ostream& operator << (std::ostream& os, const gf28& gf) {
		os << std::hex << (int)gf.value << " " << std::dec;
		return os;
	}

	//implicit conversion
	operator int() const { return (uint8_t)value; }

	// explicit conversion
	explicit operator int* () const { return nullptr; }
	explicit operator uint8_t* () const { return nullptr; }

	//functions
	uint8_t xtime();
	uint8_t x1time();
};
#endif