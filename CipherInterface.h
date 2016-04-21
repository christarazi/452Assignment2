#ifndef __CIPHER_INTERFACE__
#define __CIPHER_INTERFACE__

#include <string> /* For C++ strings */

using namespace std;

/**
 * This class implements the interface for a cipher.
 * It defines functions usually used in a cipher
 */
class CipherInterface
{
public:

	CipherInterface() {}

	virtual bool setKey(const unsigned char* key) { return false; }

	virtual bool setKey(const unsigned char* , const unsigned char* )
	{ return false; }

	virtual unsigned char* encrypt(const unsigned char* plaintext)
	{ return NULL; }

	virtual bool encrypt(const unsigned char* plaintextFileIn,
	                     const unsigned char* ciphertextFileOut)
	{ return false; }

	virtual unsigned char* decrypt(const unsigned char* ciphertext)
	{ return NULL; }

	virtual bool decrypt(const unsigned char* ciphertextFileIn,
	                     const unsigned char* plaintextFileOut)
	{ return false; }

	virtual ~CipherInterface() {}

protected:

};

#endif
