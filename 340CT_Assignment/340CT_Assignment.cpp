// 340CT_Assignment.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <cstdlib>

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "Key.h"
#include "CryptographyToolKit.h"

#include "sha256.h"
#include "sha512.h"
#include "rc4.h"
#include <iostream>
#include <string>

#include "..\cryptopp565\cryptlib.h"
#include "..\cryptopp565\filters.h"
#include "assert.h"
#include "..\cryptopp565\ccm.h"
#include "..\cryptopp565\aes.h"
#include "..\cryptopp565\hex.h"
#include "..\cryptopp565\osrng.h"

using CryptoPP::AutoSeededRandomPool;
using namespace std;
using std::cout;
using std::cerr;
using std::endl;

using std::string;
using std::exit;

using CryptoPP::Exception;

using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

using CryptoPP::AES;

using CryptoPP::CBC_Mode;

int main();

void aes_encryptdecrypt() {

	system("cls");
	AutoSeededRandomPool prng;
	string cipher, encoded, recovered;

	encoded.clear();
	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string plain;


	/*********************************\
	\*********************************/
	cin.ignore();
	cout << "AES Encryption" << endl;
	cout << "Please Enter plain text : ";
	getline(cin, plain);

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	cout << "key: " << encoded << endl;
	cout << "key size : " << sizeof(key) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv : " << encoded << endl;
	cout << "size of iv :" << sizeof(iv) << endl;

	/*********************************\
	\*********************************/

	try
	{
		cout << "Plain text: " << plain << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();
		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "Cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();
		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

		cout << "Recovered text: " << recovered << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	system("pause");
	main();
}

void rc4()
{
	system("cls");
	char text[999];
	cin.ignore();
	cout << "RC4 Stream Cipher Encryption" << endl;
	cout << "Please Enter Plain text : ";
	cin.getline(text, sizeof(text));


	//char str[64] = "This is a test for RC4 cypher";
	/* Test rc4 encoding and decoding here */
	CRC4 rc4;
	cout << "RC4 Encryption \n\n";
	cout << "Plain text: " << text << endl;
	rc4.Encrypt(text, "Key");
	cout << "Encoded string: " << text << endl;;
	rc4.Decrypt(text, "Key");
	cout << "Decoded string: " << text << endl;
	/* Test Base64  encoding and decoding here */
	//strcpy(text, "This is a test for Base64 cypher");

	//getchar();
	system("pause");
	main();
}

void sha256() {

	system("cls");
	cin.ignore();
	char i;

	do {
		string input;
		cout << "Sha256 Encryption" << endl;
		cout << "Please input Plain Text: ";
		getline(cin, input);


		string output1 = sha256(input);

		cout << "SHA 256('" << input << "'):" << output1 << endl;
		cout << "Do you want to continue? (y/n) ";
		cin >> i;
		cin.ignore();

	} while (i == 'y' || i == 'Y');
	if (i == 'n' || i == 'N') {
		cout << "Thank you !" << endl;
		main();
	}
	else {
		cout << "Wrong input !" << endl;
	}
	//system("pause");
}

void hmacsha() {

	Cryptography::CryptographyToolkit tool;


	cout << "Key Generator for HMACSHA" << endl;
	// Every 8 bits = 1 bytes
	// Note** Key gen only able factor of 4 bytes(32 bits)
	cout << "Generate 4 byte key: " << tool.keygen(32) << endl;
	cout << "Generate 8 byte key: " << tool.keygen(64) << endl;
	cout << "Generate 12 byte key: " << tool.keygen(128) << endl;
	cout << "Generate 32 byte key: " << tool.keygen(256) << endl;
	cout << "Generate 64 byte key: " << tool.keygen(512) << endl;

	const unsigned int BLOCKSIZE = (1024 / 8); // 128 byte

	system("cls");

	string message;
	string key;
	int choice,i;

	do
	{
		cout << "Please select your length of key" << endl;
		cout << "1. 32bit Key" << endl;
		cout << "2. 64bit Key" << endl;
		cout << "3. 128bit Key" << endl;
		cout << "4. 256bit Key" << endl;
		cout << "5. 512bit Key" << endl;
		cout << "choice? ";

		cin >> choice;

		if (choice == 1)
		{
			system("cls");
			cout << "32bit key : " << tool.keygen(32) << endl;
			key = tool.keygen(32);
		}
		else if (choice == 2)
		{
			system("cls");
			cout << "64bit key : " << tool.keygen(64) << endl;
			key = tool.keygen(64);
		}
		else if (choice == 3)
		{
			system("cls");
			cout << "128bit key : " << tool.keygen(128) << endl;
			key = tool.keygen(128);
		}
		else if (choice == 4)
		{
			system("cls");
			cout << "256bit key : " << tool.keygen(256) << endl;
			key = tool.keygen(256);

		}
		else if (choice == 5)
		{
			system("cls");
			cout << "512bit key : " << tool.keygen(512) << endl;
			key = tool.keygen(512);
		}
		else
		{
			cout << "Invalid selection" << endl;
		}
	} while (choice < 0 || choice > 5);

	cout << "Please enter message: ";
	cin.ignore();
	getline(cin, message);

	if (key.length() > BLOCKSIZE) {
		key = sha512(key);
	}
	while (key.length() < BLOCKSIZE) {
		key = key + (char)0x00;
	}

	string o_key_pad = key;
	for (unsigned int i = 0; i < BLOCKSIZE; i++) {
		o_key_pad[i] = key[i] ^ (char)0x5c;
	}

	string i_key_pad = key;
	for (unsigned int i = 0; i < BLOCKSIZE; i++) {
		i_key_pad[i] = key[i] ^ (char)0x36;
	}

	string output = sha512(o_key_pad + sha512(i_key_pad + message));

	cout << "Plain text : " << message << endl;
	cout << "hmac-sha512 : " << output << endl;
	main();
}

int main()
{
	int choice;
	system("cls");

	do
	{
		cout << "Choose your encryption method" << endl;
		cout << "1. AES" << endl;
		cout << "2. RC4" << endl;
		cout << "3. SHA256" << endl;
		cout << "4. HMACSHA" << endl;
		cout << "choice? : ";
		cin >> choice;

		if (choice == 1)
		{
			aes_encryptdecrypt();
		}
		else if (choice == 2)
		{
			rc4();
		}
		else if (choice == 3)
		{
			sha256();
		}
		else if (choice == 4)
		{
			hmacsha();
		}
		else
		{
			cout << endl;
			cout << "Invalid selection." << endl;
		}
	} while (choice < 0 || choice > 4);


	return 0;
}

