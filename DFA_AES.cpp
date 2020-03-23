#define _CRT_SECURE_NO_WARNINGS
//#define _NPRINT_DFA
#define _NPRINT_BITFAULT
#define _NPRINT_BYTEFAULT
#define _NPRINT_READFILE
//#define _LOAD_SAMPLEDATA


#include "DFA_AES.h"
#include "gf28.h"
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

void bitFault(vector<DFA_info> data, uint8_t key[16]);

void byteFault(vector<DFA_info> data, uint8_t key[16]);

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
    std::cout << "\nCorrect:"; phex(state);
    
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

            std::cout << "\nFaulty :"; phex(state2);
            for (unsigned int i = 0; i < 16; i++)
                tempDFA.state[i / 4][i % 4] = state2[i / 4][i % 4];
            tempDFA.correct = true;
            data.push_back(tempDFA);
        }
    }
    return data;
}

//Returns vector with the fault analysis data such that the first component is the faultless output.
vector<DFA_info> readFile(string _file);



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
    std::cout << "\nKey : \t\t = "; phex(key, 16);
    std::cout << "\nRKey: \t\t = "; phex(rkey_t, 176);

    for (unsigned i = 0; i < 16; i++)
        K10[i] = rkey_t[176 - 16 + i];
    std::cout << "\nK10 : \t\t = "; phex(K10, 16);

    std::cout << "\n\n --------------------- --------------------- --------------------- \n\n";

    keyReduction(rkey, K10);
    std::cout << "\nRKey: \t\t = "; phex(rkey, 176);

    uint8_t key2[16] = { 0 };
    for (unsigned i = 0; i < 16; i++)
        key2[i] = rkey[i];
    std::cout << "\nKey2: \t\t = "; phex(key2, 16);
}


int main() {
    //test_keyRetrieval();
    string file = "bitFault.txt";
    vector<DFA_info> data;
    uint8_t key[16] = { 0 }, rkey[176] = { 0 }, plain_text[16] = { 0 };

//----------------- Bit fault attack
    /*
    cout << "1. Bit fault attack: \n";
    //Ciphertexts read from file. [0] is the correct (no fault injected) text.
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
        */
//----------------- Byte fault attack
    std::cout << "\n\n2.Byte fault attack:";
    file = "byteFault.txt";
    data = readFile(file);
    if (data.size() == 0) {
        std::cout << "\nError: Could not find the file " << file;
        return 1;
    }

    byteFault(data, key);
}

vector<int> differentbytes(state_t arg1, state_t arg2);

struct keyPair {
    int key;
    int key2;
};

bool first = true;
void byteFault(vector<DFA_info> data, uint8_t key[]) {
    vector<keyPair> keys[16];

#ifdef _LOAD_SAMPLEDATA
    uint8_t a[] =     { 0b11101110, 0b01111111, 0b11110100, 0b01100101,
                        0b01011000, 0b01001101, 0b10110101, 0b10110101,
                        0b11111001, 0b00101001, 0b11010010, 0b11100010,
                        0b10000101, 0b00111011, 0b11111100, 0b11110111 };

    uint8_t f1[] = {    0b00101111, 0b01111111, 0b11110100, 0b01100101,
                        0b01011000, 0b01001101, 0b10110101, 0b11111111,
                        0b11111001, 0b00101001, 0b01111000, 0b11100010,
                        0b10000101, 0b10010101, 0b11111100, 0b11110111 };

    uint8_t a2[] = {    0b00001101, 0b11111101, 0b00111011, 0b10001101,
                        0b11000110, 0b00100011, 0b11110101, 0b01110001,
                        0b11001111, 0b00101110, 0b10100101, 0b11011010,
                        0b01110011, 0b00001111, 0b10101101, 0b11000100 };
    uint8_t f2[] = {    0b01011100, 0b11111101, 0b00111011, 0b10001101,
                        0b11000110, 0b00100011, 0b11110101, 0b10100001,
                        0b11001111, 0b00101110, 0b11111011, 0b11011010,
                        0b01110011, 0b00011011, 0b10101101, 0b11000100 };

    for (unsigned int i_data = 1; i_data <=2; i_data++) {
        for (int i = 0; i < 16; i++) {
            if (first) {
                data[0].state[i % 4][i / 4] = a[i];
            }
            else {
                data[0].state[i % 4][i / 4] = a2[i];
            }
            data[1].state[i % 4][i / 4] = f1[i];
            data[2].state[i % 4][i / 4] = f2[i];
        }
        first = false;
        cout << "\nCorrect   : "; phex(data[0].state);
#else
    cout << "\nCorrect   : "; phex(data[0].state);
    for (unsigned int i_data = 1; i_data < data.size(); i_data++) {
#endif
    
        //Determine different bytes
        cout << "\nFaulty " << i_data << ": "; phex(data[i_data].state);
        vector<int>  ind = differentbytes(data[0].state, data[i_data].state); // Index of the bytes that chage (thus of K10)
        cout << "\n\t\tDifferent bytes: "; for (int i = 0; i < ind.size(); i++) cout << ind[i] << " ";

        gf28  C[4]; //Correct ciphertext finite field bytes
        gf28  D[4]; //Faulty  ciphertext finite field bytes

        for (int i : ind) {
            //C.push_back(data[0].state[i / 4][i % 4]);
            //D.push_back(data[i_data].state[i / 4][i % 4]);
            C[i % 4] = (data[0].state[i / 4][i % 4]);
            D[i % 4] = (data[i_data].state[i / 4][i % 4]);
        }

        cout << "\n\t\tValues C: "; for (gf28 i : C) cout << i << " ";
        cout << "\n\t\tValues D: "; for (gf28 i : D) cout << i << " ";

        int K2;
        int arr_K1[256] = { 0 }, arr_K2[256] = { 0 },arr_K3[256] = { 0 }, arr_K4[256] = { 0 };
        
        //Check the first different element to know wich 'set of equations' use
        unsigned equ1_R = ind[0] % 4 + 1;
        unsigned equ1_L = (equ1_R - 1) % 4;
        unsigned equ2_L = (equ1_R + 1) % 4;
        unsigned equ3_L = (equ1_R + 2) % 4;

        vector<keyPair> _K[4];// , _K2, _K3, _K4;
        for (K2 = 0; K2 < 256; K2++) {
            vector<keyPair> temp_K[4];// 1, temp_K2, temp_K3, temp_K4;
            keyPair tKey, tKey2;

            tKey.key2 = K2;
            tKey2.key = K2;

            for (int K = 0; K < 256; K++) { // This is either K1,K3 or K4
                tKey.key = K; 

                if (ISB(C[0] + K) + ISB(D[0] + K) == (ISB(C[1] + K2) + ISB(D[1] + K2)) * 0x02) {
                    temp_K[0].push_back(tKey); tKey2.key2 = K;
#ifndef _NPRINT_BYTEFAULT
                    cout << "\nPartial Solution K2=" << K2 << " K1= " << K;
#endif
                }
                if ((ISB(C[2] + K) + ISB(D[2] + K))==ISB(C[1] + K2) + ISB(D[1] + K2) ) {
                    temp_K[2].push_back(tKey); tKey2.key2 = K;
#ifndef _NPRINT_BYTEFAULT
                    cout << "\nPartial Solution K2=" << K2 << " K3= " << K;
#endif
                }
                if (ISB(C[3] + K) + ISB(D[3] + K) == (ISB(C[1] + K2) + ISB(D[1] + K2)) *  0x03) {
                    temp_K[3].push_back(tKey); tKey2.key2 = K;
#ifndef _NPRINT_BYTEFAULT
                    cout << "\nPartial Solution K2=" << K2 << " K4= " << K;
#endif
                }
            }
            //Intersection of solutions for K2
            if (temp_K[0].size() && temp_K[2].size() && temp_K[3].size()) { //If all vectors are not empty
                _K[0].insert(_K[0].end(), temp_K[0].begin(), temp_K[0].end());
                _K[1].push_back(tKey2);
                _K[2].insert(_K[2].end(), temp_K[2].begin(), temp_K[2].end());
                _K[3].insert(_K[3].end(), temp_K[3].begin(), temp_K[3].end());
            } 
        }

        if (keys[ind[0]].size() == 0) { //If the solution set is empty, then add the vector.
            for (int indi:ind)
                keys[indi].insert(keys[indi].begin(), _K[indi % 4].begin(), _K[indi % 4].end()); 
        }
        else {
            //Intersection with the set of all solutions ok K
            for (int indi : ind){
                for (unsigned c_1 = 0; c_1 < keys[indi].size(); c_1++) {
                    bool found = false;
                    for (unsigned c_2 = 0; c_2 < _K[indi % 4].size(); c_2++)
                        if (keys[indi][c_1].key2 == _K[indi % 4][c_2].key2 && 
                           (keys[indi][c_1].key  == _K[indi % 4][c_2].key))
                            found = true;
                    if (!found) {
                        keys[indi].erase(keys[indi].begin() + c_1);
                        c_1--;
                    }
                }
            }
        }



        cout << keys[ind[0]][0].key;

            
            /*
            if (!(arr_K1[i] && arr_K3[i] && arr_K4[i])) { //Intersection with the current solution
                keys[diffBytes[0]][i] = 0; //K1
                keys[diffBytes[1]][i] = 0; //K2
                keys[diffBytes[2]][i] = 0; //K3
                keys[diffBytes[3]][i] = 0; //K4
            }
            else{
                if (!(keys[diffBytes[0]][i] && keys[diffBytes[2]][i] && keys[diffBytes[3]][i])) {//Intersection with previous solutions
                    keys[diffBytes[0]][i] = 0; //K1
                    keys[diffBytes[1]][i] = 0; //K2
                    keys[diffBytes[2]][i] = 0; //K3
                    keys[diffBytes[3]][i] = 0; //K4
                }
                else {
                    keys[diffBytes[0]][i] = arr_K1[i]; //K1
                    keys[diffBytes[1]][i] = i;  //K2
                    keys[diffBytes[2]][i] = arr_K3[i]; //K3
                    keys[diffBytes[3]][i] = arr_K4[i]; //K4
                }
            }
        }

        //Save the options for keys
        for (unsigned i = 0; i < 256; i++) {
            if (keys[diffBytes[0]][i])
                cout << "\nK1: " << keys[diffBytes[0]][i] << " - K2: " << keys[diffBytes[1]][i] <<
                " - K3: " << keys[diffBytes[2]][i] << " - K4:"  << keys[diffBytes[3]][i];
        }
        */
       


    }
}

vector<int> differentbytes(state_t arg1, state_t arg2) {
    vector<int> ret;
    for (int i = 0; i < 16; i++)
        if (arg1[i / 4][i % 4] != arg2[i / 4][i % 4]) ret.push_back(i);
    return ret;
}




void bitFault(vector<DFA_info> data, uint8_t key[16]) {
    uint8_t count[16][256] = { 0 };
    //Change i to 1
    for (unsigned int i_data = 1; i_data < data.size(); i_data++) {
        int cf = 0; //Count of found possible values for M9 from one string
        state_t _xor;
        //We do C xor D
        XOR((uint8_t*)_xor, (uint8_t*)data[i_data].state, (uint8_t*)data[0].state);

#ifndef _NPRINT_DFA
        std::cout << "\n\nFaulty     :\t"; phex(data[i_data].state);
        std::cout << "\nCorrect    :\t"; phex(data[0].state);
        std::cout << "\nXOR        :\t"; phex(_xor); //phex((uint8_t*) _xor,16);
#endif
        uint8_t xorj, j0 = 0, sr_j = 0;
        for (sr_j = 0; sr_j < 16; sr_j++)
            if ((xorj = _xor[sr_j % 4][sr_j / 4]) != 0) break;

        InvShiftRows((state_t*)_xor);
        std::cout << "\niSRows(XOR):\t"; phex(_xor);


        //Find the value for j
        for (j0 = 0; j0 < 16; j0++)
            if (_xor[j0 % 4][j0 / 4] != 0) break;

#ifndef _NPRINT_DFA
        std::cout << "\nShiftRows(j)=" << (int)sr_j << "\tj=" << (int)j0
            << "\tCj xor Dj="; phex((uint8_t*)xorj, 1);
        std::cout << "\nCandidates: ";
#endif
        if (xorj == 185) continue;

        //Guess different bit errors

        for (uint8_t e : e_arr) {
            //for (unsigned int count_e = 1; count_e <= 128; count_e *= 2) {
            //    uint8_t e = (uint8_t)count_e;
            for (unsigned int x = 0; x < 256; x++) {
                //uint8_t Mj = (uint8_t)x;
                uint8_t temp = byte_sbox((uint8_t)x ^ e);
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
                    std::cout << " -> " << x << " ";
                    count[j0][x]++;
                    cf++;
                }
            }
        }
        std::cout << "\n -> ";
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


    std::cout << "\n\nM9   = \t\t"; phex((uint8_t*)M9, 16);

    SubBytes((state_t*)M9);
    ShiftRows((state_t*)M9);

    std::cout << "\nS(M9)= \t\t"; phex((uint8_t*)M9, 16);
    std::cout << "\nC    = \t\t"; phex((uint8_t*)data[0].state, 16);
    XOR(*K10, *M9, *data[0].state);
    std::cout << "\nK10  = \t\t"; phex((uint8_t*)K10, 16);

    //Retrieve the original key from this
    uint8_t RoundKey[176];

    keyReduction(RoundKey, *K10);

    for (unsigned i = 0; i < 16; i++)
        key[i] = RoundKey[i];
}

/*void phex(vector< uint8_t> str)
{
    std::cout << "\t";
    for (unsigned int i = 0; i < str.size(); ++i) {
        printf("%.2x", str[i]);
        if (i % 16 == 15 && i != str.size() - 1)
            std::cout << "\n\t\t\t";
    }
}*/

void phex(uint8_t str[], int len){
    std::cout << "\t";
    if (len == 1)
        printf("%.2x", (int)str);
    else
        for (unsigned i = 0; i < len; ++i) {
            printf("%.2x", str[i]);
            if (i % 16 == 15 && i != len - 1)
                std::cout << "\n\t\t\t";
        }

}

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

//Returns vector with the fault analysis data such that the first component is the faultless output.
vector<DFA_info> readFile(string _file) {
    vector<DFA_info> data;
    int len = 42, bit0 = 8;
    char* word = (char*)malloc(len * sizeof(char));

    std::cout << "\nLoading " << _file;
    FILE* fp = fopen(_file.c_str(), "r");
    if (fp == NULL) return data;

    DFA_info tem_info;

    //Read first line (Correct input)
    string strTemp(fgets(word, len, fp));
    for (unsigned int i = 0; i < 16; i++)
        tem_info.state[i / 4][i % 4] = ((uint8_t)stoi(strTemp.substr(bit0 + i * 2, 2), 0, 16));
    tem_info.correct = true;
    data.push_back(tem_info);
#ifndef _NPRINT_READFILE
    std::cout << "\nCorrect: \t"; phex((uint8_t*)tem_info.state, 16);
#endif
    //Read the following lines (Faulty inputs)
    while (fgets(word, len, fp) != 0) {
        strTemp = string(word);
        for (unsigned int i = 0; i < 16; i++)
            tem_info.state[i / 4][i % 4] = ((uint8_t)stoi(strTemp.substr(bit0 + i * 2, 2), 0, 16));
        tem_info.correct = false;
        data.push_back(tem_info);
#ifndef _NPRINT_READFILE
        std::cout << "\nFaulty: \t"; phex((uint8_t*)tem_info.state, 16);
#endif
    }
    free(word);
    fclose(fp);
    return data;
}
