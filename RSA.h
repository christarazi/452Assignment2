
#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include <ctype.h>
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <vector>
#include <iterator>
#include "CipherInterface.h"

using namespace std;

/** 
 * Implements an RSA cipher
 */
class RSA_452: public CipherInterface
{
    /* The public members */
public:
    
    /**
     * The default constructor
     */
    RSA_452(){}
    
    /**
     * NOTE: This is used for RSA.
     * Sets the key pair to use. 
     * @param  publicKeyFile  - the file containing the public key.
     * @param  privateKeyFile - the file containing the private key.
     * @return                - true if setting key succeeded; false otherwise.
     */
    virtual bool setKey(const unsigned char* publicKeyFile, const unsigned char* privateKeyFile);
    
    /**
     * Encrypt the file at plaintextFileIn and output at ciphertextFileOut.
     * @param  plaintextFileIn   - the file to encrypt.
     * @param  ciphertextFileOut - the encrypted output file.
     * @return 					 - void
     */
    virtual void encrypt(const unsigned char* plaintextFileIn,
                         const unsigned char* ciphertextFileOut);
    
    /**
     * Decrypt the file at ciphertextFileIn and output at plaintextFileOut.
     * @param  ciphertextFileIn - the file to decrypt.
     * @param  plaintextFileOut - the decrypted output file.
     * @return                  - void
     */
    virtual void decrypt(const unsigned char* ciphertextFileIn,
                         const unsigned char* plaintextFileOut);
    
    /**
     * The default destructor.
     */
    virtual ~RSA_452();
    
    /* The private members */
private:
    RSA* pubKey;
    RSA* privKey;
    
};


#endif
