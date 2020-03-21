#define _CRT_SECURE_NO_WARNINGS
//#define _NPRINT_DFA
#define _NPRINT_BITFAULT

#include "DFA_AES.h"
#include <stdio.h>
#include <stdint.h>
#include <iostream>

#include <string>
#include <vector>
#include <set>


using namespace std;
uint8_t e_arr[8] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

class AES_byte {
public:
    uint8_t byte;
    uint8_t count;

    bool operator < (AES_byte const& obj) const;
};
bool AES_byte::operator<(AES_byte const& obj) const {
    //We overload this operator so that when creating a set, it gets sorted with the highest one first
    if (this->byte == obj.byte)
        return false;
    if (count == obj.count)
        return this->byte > obj.byte;
    return this->count > obj.count;
}


class DFA_info {
public:
    state_t state;
    bool correct;
};

void test_keyRetrieval() {
    uint8_t key[16] = { 0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00, };
    string strKey = "f1e3d1b26ae789029b1c81a4640a2618";
    //for (unsigned int i = 0; i < 16; i++)
    //    key[i] = ((uint8_t)stoi(strKey.substr(i * 2, 2), 0, 16));

    uint8_t rkey[176] = { 0 }, rkey_t[176] = { 0 }, K10[16] = { 0 };



    KeyExpansion(rkey_t, key);
    cout << "\nKey : \t\t = "; phex(key, 16);
    cout << "\nRKey: \t\t = "; phex(rkey_t, 176);

    for (unsigned i = 0; i < 16; i++)
        K10[i] = rkey_t[176 - 16 + i];
    cout << "\nK10 : \t\t = "; phex(K10, 16); 
    
    cout << "\n\n --------------------- --------------------- --------------------- \n\n";

    keyReduction(rkey, K10);
    cout << "\nRKey: \t\t = "; phex(rkey, 176);

    uint8_t key2[16] = { 0 };
    for (unsigned i = 0; i < 16; i++)
        key2[i] = rkey[i];
    cout << "\nKey2: \t\t = "; phex(key2, 16);

}

void bitFault(vector<DFA_info> data, uint8_t key[16]) {
    uint8_t count[16][256] = {0};
    //Change i to 1
    for (unsigned int i_data = 1; i_data < data.size(); i_data++) {
        int cf = 0; //Count of found possible values for M9 from one string
        state_t _xor;
        //We do C xor D
        XOR((uint8_t*)_xor, (uint8_t*)data[i_data].state, (uint8_t*)data[0].state);

#ifndef _NPRINT_DFA
        cout << "\n\nFaulty     :\t"; phex(data[i_data].state);
        cout <<   "\nCorrect    :\t"; phex(data[0].state);
        cout <<   "\nXOR        :\t"; phex(_xor); //phex((uint8_t*) _xor,16);
#endif
        uint8_t xorj , j0=0, sr_j=0;
        for (sr_j = 0; sr_j < 16; sr_j++)
            if ((xorj = _xor[sr_j % 4][sr_j / 4]) != 0) break;
            
        InvShiftRows((state_t*)_xor);
        cout << "\niSRows(XOR):\t"; phex(_xor);


        //Find the value for j
        for (j0 = 0; j0 < 16; j0++)
            if (_xor[j0 % 4][j0 / 4]  != 0) break;

#ifndef _NPRINT_DFA
        cout << "\nShiftRows(j)=" << (int)sr_j<< "\tj=" << (int) j0
             << "\tCj xor Dj="; phex((uint8_t*)xorj, 1);
        cout << "\nCandidates: ";
#endif
        if (xorj == 185) continue;

        //Guess different bit errors
        
        for (uint8_t e : e_arr){
        //for (unsigned int count_e = 1; count_e <= 128; count_e *= 2) {
        //    uint8_t e = (uint8_t)count_e;
            for (unsigned int x = 0; x < 256; x++) {
                //uint8_t Mj = (uint8_t)x;
                uint8_t temp  = byte_sbox((uint8_t)x ^ e);
                uint8_t temp2 = byte_sbox((uint8_t)x);
                uint8_t xort = temp ^ temp2;

#ifndef _NPRINT_BITFAULT
                cout << "\nMj: "; phex((uint8_t*)x, 1);
                cout << "  ej: "; phex((uint8_t*)e, 1);
                cout << "  Mj^ej: "; phex((uint8_t*)(x ^ e), 1);

                cout << "\tSB(Mj^ej): "; phex((uint8_t*)temp, 1);
                cout << "  SB(Mj) : "; phex((uint8_t*)temp2, 1);
                cout << "  xor: "; phex((uint8_t*)xort, 1);
#endif


                if (xort == xorj) {
                    cout << " -> " << x << " ";
                    count[j0][x]++;
                    cf++;
                }
            }
        }
        cout << "\n -> " ;
    }

    //We pass the data found to a vector of sorted sets
    vector< set<AES_byte>> vect_M(16);
    for (int j = 0; j < 16; j++) {
        set<AES_byte> Mj_c;
        for (int k = 0; k < 256; k++) {
            if (count[j][k] != 0) {
                AES_byte temp_byte;
                temp_byte.byte = k;
                temp_byte.count = count[j][k];
                Mj_c.insert(temp_byte);
            }
        }
        vect_M[j] = Mj_c;
    }

    //Build the AES state M9 using the most counted byte

    state_t M9, K10;
    for (unsigned i = 0; i < 16; i++) {
        M9[i % 4][i / 4] = (uint8_t)getSetAt(vect_M[i], 0).byte;
    }
    
    
    cout << "\n\nM9   = \t\t"; phex((uint8_t*)M9, 16);

    SubBytes((state_t*)M9);
    ShiftRows((state_t*)M9);

    cout <<   "\nS(M9)= \t\t"; phex((uint8_t*)M9, 16);
    cout <<   "\nC    = \t\t"; phex((uint8_t*)data[0].state, 16);
    XOR(*K10, *M9, *data[0].state);
    cout <<   "\nK10  = \t\t"; phex((uint8_t*)K10, 16);

    //Retrieve the original key from this
    uint8_t RoundKey[176];

    keyReduction(RoundKey, *K10);

    for (unsigned i = 0; i < 16; i++)
        key[i] = RoundKey[i];
}

void stateCopy(uint8_t text[], state_t state) {
    for (int i = 0; i < 16; i++)
        state[i % 4][i / 4] = text[i] ;
}

//Generetaes a set of faulty ciphertext introducing an error in M9 on each byte and each bit
vector<DFA_info> generateFaulty(uint8_t key[16], uint8_t text[16]) {
    vector<DFA_info> data;
    uint8_t rkey[176] = { 0 };

    KeyExpansion(rkey, key);

    state_t state;
    DFA_info tempDFA;
    stateCopy(text, state);
    Cipher((state_t*)state, rkey);
    cout << "\nCorrect:"; phex(state);
    
    for (unsigned int i = 0; i < 16; i++)
        tempDFA.state[i / 4][i % 4] = state[i / 4][i % 4];
    tempDFA.correct = true;
    data.push_back(tempDFA);

    for (int byte = 0; byte < 16; byte++) {
        for (uint8_t e : e_arr) {
            //cout << "\n";
            state_t state2;
            stateCopy(text, state2);
            Cipher_biterror((state_t*)state2, rkey, byte, e);

            cout << "\nFaulty :"; phex(state2);
            for (unsigned int i = 0; i < 16; i++)
                tempDFA.state[i / 4][i % 4] = state2[i / 4][i % 4];
            tempDFA.correct = true;
            data.push_back(tempDFA);
        }
    }

    return data;
}

//Returns vector with the fault analysis data such that the first component is the faultless output.
vector<DFA_info> readFile(string _file) {
    vector<DFA_info> data;
    int len = 42, bit0 = 8;
    char* word = (char*)malloc(len * sizeof(char));
    
    cout << "\nLoading " << _file;
    FILE* fp = fopen(_file.c_str(), "r");
    if (fp == NULL) return data;
        
    DFA_info tem_info;

    //Read first line (Correct input)
    string strTemp(fgets(word, len, fp));
    for (unsigned int i = 0; i < 16; i++)
        tem_info.state[i / 4][i % 4] = ((uint8_t)stoi(strTemp.substr(bit0 + i * 2, 2), 0, 16));
    tem_info.correct = true;
    data.push_back(tem_info);
#ifndef _NPRINT_DFA
    cout << "\nCorrect: \t"; phex((uint8_t*)tem_info.state, 16);
#endif
    //Read the following lines (Faulty inputs)
    while (fgets(word, len, fp) != 0) {
        strTemp = string(word);
        for (unsigned int i = 0; i < 16; i++)
            tem_info.state[i / 4][i % 4] = ((uint8_t)stoi(strTemp.substr(bit0 + i * 2, 2), 0, 16));
        tem_info.correct = false;
        data.push_back(tem_info);
#ifndef _NPRINT_DFA
        cout << "\nFaulty: \t"; phex((uint8_t*)tem_info.state, 16);
#endif
    }
    free(word);
    fclose(fp);
    return data;
} 




int main() {
test_keyRetrieval();

//----------------- Bit fault attack
    cout << "1. Bit fault attack: \n";
    vector<DFA_info> data; //Ciphertexts read from file. [0] is the correct (no fault injected) text.
    string file ="bitFault.txt" ; 
    uint8_t key[16] = { 0 }, rkey[176] = { 0 }, plain_text[16] = { 0 };

    data = readFile(file);
    //data = generateFaulty(key, plain_text);



    if (data.size() == 0) {
        cout << "\nError: Could not find the file " << file;
        return 1;
    }
   
    bitFault(data,key);
    KeyExpansion(rkey, key);

    cout << "\nKey Retreived:";
    cout << "\nKey = \t\t"; phex(key, 16);
    cout << "\nRKey= \t\t"; phex(rkey, 176);

    state_t state;
    for (int i = 0; i < 16; i++)
        state[i/4][i%4] = data[0].state[i/4][i%4];
    
    InvCipher(&state, rkey);
    cout << "\n\nPlain Text=\t\t";
    for (int i = 0; i < 16; i++)
        cout << state[i / 4][i % 4];

//----------------- Byte fault attack
    cout << "\n\n2.Byte fault attack:";
    file = "byteFault.txt";
    data = readFile(file);
    if (data.size() == 0) {
        cout << "\nError: Could not find the file " << file;
        return 1;
    }

}


void phex(vector< uint8_t> str)
{
    cout << "\t";
    for (unsigned int i = 0; i < str.size(); ++i) {
        printf("%.2x", str[i]);
        if (i % 16 == 15 && i != str.size() - 1)
            cout << "\n\t\t\t";
    }
}

void phex(uint8_t str[], int len){
    cout << "\t";
    if (len == 1)
        printf("%.2x", (int)str);
    else
        for (int i = 0; i < len; ++i) {
            printf("%.2x", str[i]);
            if (i % 16 == 15 && i != len - 1)
                cout << "\n\t\t\t";
        }

}

/*void phex(state_t state){
    cout << "\t";
    for (int i = 0; i < 16; ++i) {
        printf("%.2x", state[i/4][i%4]);
        if (i % 16 == 15 && i != 15)
            cout << "\n\t\t\t";
    }
}*/

void XOR(uint8_t outArr[], uint8_t byteArr1[], uint8_t byteArr2[]) {
    //AESstate outArr(16);
    for (unsigned  i = 0; i < 16; i++)
        outArr[i] = byteArr1[i] ^ byteArr2[i];
    return;
}

template <typename T>
T getSetAt(std::set<T>& searchSet, unsigned int n)
{
    T result;
    if (searchSet.size() > n)
        result = *(std::next(searchSet.begin(), n));
    return result;
}

static unsigned N = 4, R = 11;

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

void keyReduction(uint8_t RoundKey[], const uint8_t Key[]){
    unsigned j, k;
    uint8_t tempa[4]; // Used for the column/row operations

    // The 10th round key is the one obtained itself.
    unsigned maxi = 4 * N * R ;
    for (unsigned i = 0; i <16; i++)
        RoundKey[maxi-16+i] = Key[i];
    
    // All other round keys are found from the previous round keys.
    for (signed int i = (4*R)-1; i > 3; i--)    {
        k = (i-1)*4;

        tempa[0] = RoundKey[k + 0];
        tempa[1] = RoundKey[k + 1];
        tempa[2] = RoundKey[k + 2];
        tempa[3] = RoundKey[k + 3];
       

        if (i % 4 == 0){
            RotWordL(tempa);
            SubWord(tempa);
            tempa[0] = tempa[0] ^ Rcon[i / 4];
        }

        j = (i-4) * 4;
        RoundKey[j + 0] = RoundKey[k+4 + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k+4 + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k+4 + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k+4 + 3] ^ tempa[3];
    }
}


//Applies the Byte level AES Substitution Box
void SubWord(uint8_t word[]) {
    for (unsigned i = 0; i < 4; i++)
        word[i] = byte_sbox(word[i]);
    /*word[0] = byte_sbox(word[0]);
    word[1] = byte_sbox(word[1]);
    word[2] = byte_sbox(word[2]);
    word[3] = byte_sbox(word[3]);*/
}

//Applies the inverse Byte level AES Substitution Box
void RSubWord(uint8_t word[]){
    for (unsigned i = 0;i<4;i++)
        word[i] = byte_rsbox(word[i]);
}

// Byte level roattion to the right.
void RotWordR(uint8_t word[]){
    const uint8_t u8tmp = word[3];
    word[3] = word[2];
    word[2] = word[1];
    word[1] = word[0];
    word[0] = u8tmp;
}

// Byte level roattion to the right.
void RotWordL(uint8_t* word) {
    const uint8_t u8tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = u8tmp;
}