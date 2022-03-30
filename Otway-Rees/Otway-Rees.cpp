#include <iostream>
#include <string> 
#include <cmath>
#include <tuple>
#include <vector>
#include <typeinfo>

#include "../cryptopp860/cryptlib.h"
#include "../cryptopp860/modes.h"
#include "../cryptopp860/filters.h"
#include "../cryptopp860/osrng.h" // PNG AutoSeededRandomPool
#include "../cryptopp860/integer.h"
#include "../cryptopp860/nbtheory.h"
#include "../cryptopp860/hex.h"
#include "../cryptopp860/algebra.h"
#include "../cryptopp860/secblock.h"
#include "../cryptopp860/aes.h"
#include "../cryptopp860/files.h"
#include "../cryptopp860/config_int.h"
#include "../cryptopp860/des.h" // DES algorithm


using namespace CryptoPP;
using namespace std;

const unsigned int SIZE = 16;

//������� ��������� �������� �����
Integer get_prime(unsigned int bytes) {
    AutoSeededRandomPool prng;
    Integer x;
    do {
        x.Randomize(prng, bytes);
    } while (!IsPrime(x));

    return x;
}

// ������� ��������� ��������� ������
string generate_k() {
    AutoSeededX917RNG<DES_EDE3> prng;
    string encoded;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);

    prng.GenerateBlock(key, key.size());

    StringSource(key, key.size(), true, new HexEncoder(new StringSink(encoded)));

    return encoded;
}

// ������� ����������, � ������� AES
string aes_encoder(string strkey, string plain) {
    byte iv[AES::DEFAULT_KEYLENGTH];
    for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
        iv[i] = 0;

    byte key[AES::DEFAULT_KEYLENGTH];
    byte* k = (byte*)strkey.c_str();

    for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
        if (i < sizeof(k))
            key[i] = k[i];
        else
            key[i] = 0;

    string ciphertextEncode, ciphertext;

    ciphertextEncode.clear();
    ciphertext.clear();

    AES::Encryption aesEncryption(key, AES::DEFAULT_KEYLENGTH);
    CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(ciphertext), StreamTransformationFilter::PKCS_PADDING);
    stfEncryptor.Put(reinterpret_cast<const unsigned char*> (plain.c_str()), plain.length() + 1);

    StringSource ss(ciphertext, true, new HexEncoder(new StringSink(ciphertextEncode)));

    return ciphertextEncode;
}

// ������� �������������, � ������� AES
string aes_decoder(string strkey, string cipher) {

    byte iv[AES::DEFAULT_KEYLENGTH];
    for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
        iv[i] = 0;

    byte key[AES::DEFAULT_KEYLENGTH];
    byte* k = (byte*)strkey.c_str();

    for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
        if (i < sizeof(k))
            key[i] = k[i];
        else
            key[i] = 0;

    string ciphertextDecode, decryptedtext;

    ciphertextDecode.clear();
    decryptedtext.clear();

    StringSource ss(cipher, true, new HexDecoder(new StringSink(ciphertextDecode)));

    AES::Decryption aesDecryption(key, AES::DEFAULT_KEYLENGTH);
    CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    StreamTransformationFilter stfDecryptor(cbcDecryption, new StringSink(decryptedtext), StreamTransformationFilter::PKCS_PADDING);
    
    stfDecryptor.Put(reinterpret_cast<const unsigned char*> (ciphertextDecode.c_str()), (ciphertextDecode.size() + 16));   

    return decryptedtext;
}


// ����� �������
class Cert_T {
private:
    string K_AT, K_BT, M1_des, M1_encode, s, M2, str_Na, str_Nb, M0_encode, M0_des, M0_encode1, I_B, I_A, str_I;
    Integer::Signedness sign = Integer::UNSIGNED;
    Integer I, ind_A, ind_B;

public:
    // ������� ��������� ���������� ����� ��� Alice
    string get_ka() {
        cout << "Cert T: ��������� ��������������� ���������� ����� K_AT..." << endl;
        K_AT = generate_k();
        cout << "Cert T: ������������� K_AT = " << K_AT << endl;
        return K_AT;
    }

    // ������� ��������� ���������� ����� ��� Bob
    string get_kb() {
        cout << "Cert T: ��������� ��������������� ���������� ����� K_BT..." << endl;
        K_BT = generate_k();
        cout << "Cert T: ������������� K_BT = " << K_BT << endl;
        return K_BT;
    }   

    // ������� ��������� I, A, B
    void generate_I() {
        I = get_prime(SIZE);
        cout << "Cert T: I = " << I << endl;
        cout << "Cert T: ��������� ��������������� � � �..." << endl;
        ind_A = get_prime(SIZE);
        ind_B = get_prime(SIZE);
        while (ind_A == ind_B) {
            ind_B = get_prime(SIZE);
        }
        cout << "Cert T: ������������ ������������� A = " << ind_A << endl;
        cout << "Cert T: ������������ ������������� B = " << ind_B << endl;
    }

    // ������� ��������� ���������� I, A, B
    tuple<Integer, Integer, Integer> parametrs() {

        byte key_I[AES::DEFAULT_KEYLENGTH];
        I.Encode(key_I, AES::DEFAULT_KEYLENGTH, sign);
        str_I.clear();
        StringSource(key_I, sizeof(I), true, new HexEncoder(new StringSink(str_I)));

        return make_tuple(I,ind_A, ind_B);
    }

    // ��� 3.0
    string step_3(string M1, Integer N_a, Integer N_b) {
        cout << "Cert T: �������� M1 =  " << M1 << endl;
        cout << endl;
       
        // ��������� ��������� � 1008 �������� �� 1744 �� M1
        M1_encode = M1.substr(1008, 736);
        cout << "Cert T: ������������� ����� �1 �� �. M1_� =  " << M1_encode << endl;
        cout << endl;

        // ������������� ����������
        M1_des = aes_decoder(K_BT, M1_encode);

        cout << "Cert T: �������������� ����� M1 =  " << M1_des << endl;
        cout << endl;

        cout << "Cert T: ���������� I = " << str_I << endl;

        I_B = M1_des.substr(96, 96);
        cout << "Cert T: I �� M1. I =  " << I_B << endl;

        // ��������� ��������� � 0 �������� �� 1008 �� M1, ��� ���������� M0
        M0_encode = M1.substr(0, 1008);

        // ��������� ��������� � 272 �������� �� 736 �� M0
        M0_encode1 = M0_encode.substr(272, 736);
        cout << "Cert T: ������������� ����� �0 �� �. M1_� =  " << M0_encode1 << endl;
        cout << endl;

        // ������������� ��������� 
        M0_des = aes_decoder(K_AT, M0_encode1);

        cout << "Cert T: �������������� ����� M0 =  " << M0_des << endl;
        cout << endl;

        I_A = M0_des.substr(96, 96);
        cout << "Cert T: I �� M0. I =  " << I_A << endl;

        if ((I_A == str_I) && (I_B == str_I)) {
            cout << "Cert T: ���������� �������������� �������." << endl;
            
            cout << "Cert T: ��������� ���������� ����� s..." << endl;
            s = generate_k();
            cout << "Cert T: ������������� s = " << s << endl;

            // �������������� Integer � string
            byte key_Na[AES::DEFAULT_KEYLENGTH];
            byte key_Nb[AES::DEFAULT_KEYLENGTH];
            N_a.Encode(key_Na, AES::DEFAULT_KEYLENGTH, sign);
            N_b.Encode(key_Nb, AES::DEFAULT_KEYLENGTH, sign);
            StringSource(key_Na, sizeof(N_a), true, new HexEncoder(new StringSink(str_Na)));
            StringSource(key_Nb, sizeof(N_b), true, new HexEncoder(new StringSink(str_Nb)));

            M2 = aes_encoder(K_AT, str_Na + s) + aes_encoder(K_BT, str_Nb + s);

            cout << "Cert T: ����������� M2 = " << M2 << endl;
            cout << endl;

            return M2;

        }
        else {
            return "0";
        }     
    }

    // ��������� ����� s
    string get_s() {
        cout << "Cert T: s = " << s << endl;
        return s;
    }

};

class Alice {
private:
    Integer N_a, ind_A, ind_B, I;
    string K_AT, str_Na, str_A, str_B, M0_2, str_I, M0, M2, s_sub;
    Integer::Signedness sign = Integer::UNSIGNED;

public:
    // ������� ��������� ���������� �����
    string get_K_at(Cert_T& T) {
        K_AT = T.get_ka();
        cout << "Alice: ��������� K_AT = " << K_AT << endl;
        return K_AT;
    }

    // ������� ��������� Na
    Integer get_Na() {
        cout << "Alice: ��������� ���������� ������������ ����� Na..." << endl;
        N_a = get_prime(SIZE);
        cout << "Alice: ������������� Na = " << N_a << endl;

        byte key_Na[AES::DEFAULT_KEYLENGTH];
        N_a.Encode(key_Na, AES::DEFAULT_KEYLENGTH, sign);
        StringSource(key_Na, sizeof(N_a), true, new HexEncoder(new StringSink(str_Na)));

        return N_a;
    }

    // ��������� ���������� I, A, B
    void get_par(Cert_T& T) {
        tie(I, ind_A, ind_B) = T.parametrs();
        cout << "Alice: I = " << I << ", A = " << ind_A << ", B = " << ind_B <<  endl;
        
        // ���������� ������
        // --------
        I = 666666;
        // --------


        byte key_I[AES::DEFAULT_KEYLENGTH];
        I.Encode(key_I, AES::DEFAULT_KEYLENGTH, sign);
        str_I.clear();
        StringSource(key_I, sizeof(I), true, new HexEncoder(new StringSink(str_I)));
    }

    // ��� 1.0
    string step_1() {
        byte key_a[AES::DEFAULT_KEYLENGTH];
        byte key_b[AES::DEFAULT_KEYLENGTH];

        ind_A.Encode(key_a, AES::DEFAULT_KEYLENGTH, sign);
        ind_B.Encode(key_b, AES::DEFAULT_KEYLENGTH, sign);

        str_A.clear();
        str_B.clear();
        StringSource(key_a, sizeof(ind_A), true, new HexEncoder(new StringSink(str_A)));
        StringSource(key_b, sizeof(str_B), true, new HexEncoder(new StringSink(str_B)));

        M0_2 = aes_encoder(K_AT, str_Na + str_I + str_A + str_B);

        M0 = str_I + str_A + str_B + M0_2;

        cout << "Alice: ������������ ��������� M0 = " << M0 << endl;
        cout << endl;

        return M0;
    }

    // ��� 5.0
    string step_5(string M2_A) {
        cout << "Alice: �������� ������ ����� M2 = " << M2_A << endl;
        cout << endl;

        M2 = aes_decoder(K_AT, M2_A);

        cout << "Alice: ������������ �2 = " << M2 << endl;
        cout << endl;

        return M2;
    }

    // ��������� ����� s
    string get_s() {
        s_sub = M2.substr(96, 32);

        cout << "Alice: s =  " << s_sub << endl;

        return s_sub;
    }

};

class Bob {
private:
    Integer N_b, I, ind_A, ind_B;
    string K_BT, str_Nb, M1_0, M1, str_I, str_A, str_B, M2_des, M2_B, M2_encode, M2_A, s_sub;
    Integer::Signedness sign = Integer::UNSIGNED;

public:
    // ������� ��������� ���������� �����
    string get_K_bt(Cert_T& T) {
        K_BT = T.get_kb();
        cout << "Bob: ��������� K_BT = " << K_BT << endl;
        return K_BT;
    }

    // ������� ��������� Nb
    Integer get_Nb() {
        cout << "Bob: ��������� ���������� ������������ ����� Nb..." << endl;
        N_b = get_prime(SIZE);

        byte key_Nb[AES::DEFAULT_KEYLENGTH];
        N_b.Encode(key_Nb, AES::DEFAULT_KEYLENGTH, sign);
        str_Nb.clear();
        StringSource(key_Nb, sizeof(N_b), true, new HexEncoder(new StringSink(str_Nb)));

        cout << "Bob: ������������� Nb = " << N_b << endl;
        return N_b;
    }

    // ��������� ���������� I, A, B
    void get_par(Cert_T& T) {
        tie(I, ind_A, ind_B) = T.parametrs();
        cout << "Bob: I = " << I << ", A = " << ind_A << ", B = " << ind_B << endl;

        byte key_I[AES::DEFAULT_KEYLENGTH];
        I.Encode(key_I, AES::DEFAULT_KEYLENGTH, sign);
        str_I.clear();
        StringSource(key_I, sizeof(I), true, new HexEncoder(new StringSink(str_I)));
    }

    // ��� 2.0
    string step_2(string M0) {
        cout << "Bob: �������� �0 �� Alice. M0 =  " << M0 << endl;
        cout << endl;

        byte key_a[AES::DEFAULT_KEYLENGTH];
        byte key_b[AES::DEFAULT_KEYLENGTH];

        ind_A.Encode(key_a, AES::DEFAULT_KEYLENGTH, sign);
        ind_B.Encode(key_b, AES::DEFAULT_KEYLENGTH, sign);

        str_A.clear();
        str_B.clear();
        StringSource(key_a, sizeof(ind_A), true, new HexEncoder(new StringSink(str_A)));
        StringSource(key_b, sizeof(str_B), true, new HexEncoder(new StringSink(str_B)));

        M1_0 = aes_encoder(K_BT, str_Nb + str_I + str_A + str_B);
        
        M1 = M0 + M1_0;

        cout << "Bob: ������������ ��������� M1 = " << M1 << endl;
        cout << endl;

        return M1;
    }

    // ��� 4.0
    string step_4(string M2) {
        cout << "Bob: �������� �2 �� ������ �������. M2 =  " << M2 << endl;
        cout << endl;

        M2_B = M2.substr(256, 256);

        M2_A = M2.substr(0, 256);


        M2_encode = aes_decoder(K_BT, M2_B);

        cout << "Bob: ������������ ������ �����. M2 =  " << M2_encode << endl;
        cout << endl;

        return M2_A;
    }

    // ��������� ����� s
    string get_s() {
        s_sub = M2_encode.substr(96, 32);

        cout << "Bob: s =  " << s_sub << endl;

        return s_sub;
    }

};

int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");

    Cert_T T;
    Bob B;
    Alice A;

    string M0, M1, M2, M2_A, s_B, s_A, s;
    Integer N_a, N_b;

    A.get_K_at(T);
    B.get_K_bt(T);

    N_a = A.get_Na();
    N_b = B.get_Nb();

    T.generate_I();
    
    A.get_par(T);
    B.get_par(T);

    M0 = A.step_1();
    M1 = B.step_2(M0);

    M2 = T.step_3(M1, N_a, N_b);

    if (M2 != "0") {
        M2_A = B.step_4(M2);

        A.step_5(M2_A);

        s = T.get_s();
        s_B = B.get_s();
        s_A = A.get_s();

        if ((s == s_B) && (s == s_A)) {
            cout << "Alice � Bob �������� ����� ��������� ���� s" << endl;
        }
        else {
            cout << "Error!" << endl;
        }
    }
    else {
        cout << "Cert T: ���������� �������������� �� �������" << endl;
    }

    


    system("pause");
    return 0;
}
