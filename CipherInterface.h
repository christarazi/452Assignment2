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
	/** The public members **/
public:

	/**
	 * The default constructor
	 */
	CipherInterface() {}

	/**
	 * NOTE: This is used for DES.
	 * Sets the key to use.
	 * @param key 	- the key to use.
	 * @return 		- True if the key is valid and False otherwise.
	 */
	virtual bool setKey(const unsigned char* key) { return false;  }

	/**
	 * NOTE: This is used for RSA.
	 * Sets the key pair to use.
	 * @param  publicKeyFile  - the file containing the public key.
	 * @param  privateKeyFile - the file containing the private key.
	 * @return                - true if setting key succeeded; false otherwise.
	 */
	virtual bool setKey(const unsigned char* publicKeyFile, const unsigned char* privateKeyFile)
	{
		return false;
	};

	/**
	 * Encrypt the file at plaintextFileIn and output at ciphertextFileOut.
	 * @param  plaintextFileIn   - the file to encrypt.
	 * @param  ciphertextFileOut - the encrypted output file.
	 * @return 					 - void
	 */
	virtual unsigned char* encrypt(const unsigned char* plaintext)
	{ return NULL; }

	virtual void encrypt(const unsigned char* plaintextFileIn,
	                     const unsigned char* ciphertextFileOut)
	{ return; }

	/**
	 * Decrypt the file at ciphertextFileIn and output at plaintextFileOut.
	 * @param  ciphertextFileIn - the file to decrypt.
	 * @param  plaintextFileOut - the decrypted output file.
	 * @return                  - void
	 */
	virtual unsigned char* decrypt(const unsigned char* ciphertext)
	{ return NULL; }

	virtual void decrypt(const unsigned char* ciphertextFileIn,
	                     const unsigned char* plaintextFileOut)
	{ return; }

	/**
	 * The default destructor.
	 */
	virtual ~CipherInterface() {}

	/* The protected members */
protected:

};

#endif
