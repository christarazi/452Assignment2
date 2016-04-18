#ifndef DES_H
#define DES_H

#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <string.h>
#include <string>
#include <ctype.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include "CipherInterface.h"

using namespace std;

/**
 * Implements a DES cipher
 */
class DES_452: public CipherInterface
{
	/* The public members */
public:

	/**
	 * The default constructor
	 */
	DES() {}

	/**
	 * Sets the key to use
	 * @param key - the key to use
	 * @return - True if the key is valid and False otherwise
	 */
	virtual bool setKey(const unsigned char* key);

	/**
	 * Encrypt the file at plaintextFileIn and output at ciphertextFileOut.
	 * @param  plaintextFileIn   - the file to encrypt.
	 * @param  ciphertextFileOut - the encrypted output file.
	 * @return 					 - void
	 */
	virtual void encrypt(const unsigned char* plaintextFileIn, const unsigned char* ciphertextFileOut);

	/**
	 * Decrypt the file at ciphertextFileIn and output at plaintextFileOut.
	 * @param  ciphertextFileIn - the file to decrypt.
	 * @param  plaintextFileOut - the decrypted output file.
	 * @return                  - void
	 */
	virtual void decrypt(const unsigned char* plaintextFileIn, const unsigned char* ciphertextFileOut);

	virtual ~DES() {}

	/* The protected members */
protected:

	/**
	 * Function to perform DES encryption / decryption based on desAction.
	 * @param  readBuffer - the block we want to encrypt / decrypt.
	 * @param  desAction  - the action to perform.
	 * @return desBlock   - the encrypted / decrypted block.
	 */
	vector<unsigned char> performDES(vector<unsigned char> readBuffer, int desAction);

	/**
	 * Function to perform DES in CBC mode.
	 * @param  readBlock 	- the ibput block from the file.
	 * @param  cipherBlock  - pass-by-reference vector holding the previous block for chaining.
	 * @param  initVec  	- the initialization vector.
	 * @param  action  		- the action to perform (ENC / DEC).
	 * @param  firstRun  	- indicates where this is first run through CBC or not.
	 * @return 				- return new vector based on action.
	 */
	vector<unsigned char> performCBC(vector<unsigned char> readBlock, vector<unsigned char> & cipherBlock,
	                                 vector<unsigned char> initVec, bool action, bool & firstRun);
	
	/**
	 * Function to pad a DES block if necessary.
	 * @param  readBuffer - the block we want to verify padding for.
	 * @param  bytesRead  - the number of we've read from the file.
	 * @return readBuffer - the padded buffer.
	 */
	vector<unsigned char> verifyPadding(vector<unsigned char> readBuffer, int bytesRead);

	/**
	 * Converts two characters into a hex integers
	 * and then inserts the integers into the higher
	 * and lower bits of the byte
	 */
	unsigned char twoCharToHexByte(const unsigned char* twoChars);

	/**
	 * Converts a character into a hexadecimal integer
	 * @param character - the character to convert
	 * @return - the converted character, or 'z' on error
	 */
	unsigned char charToHex(const char& character);

	/**
	 * Converts a long integer (4 bytes = 32 bits)
	 * into an array of 8 characters.
	 * @param l - the long integer to convert
	 * @param c - the character array to store the result
	 */
	void ltoc(DES_LONG l, unsigned char *c);

	/**
	 * Converts an array of 8 characters
	 * (i.e. 4 bytes/32 bits)
	 * @param c - the array of 4 characters (i.e. 1-byte per/character
	 * @return - the long integer (32 bits) where each byte
	 * is equivalent to one of the bytes in a character array
	 */
	DES_LONG ctol(unsigned char *c);

	/* The 64-bit, user-defined encryption key */
	unsigned char des_key[8];

	/* The key structure used by the DES library */
	des_key_schedule key;
};


#endif
