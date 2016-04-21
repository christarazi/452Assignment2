#ifndef MY_UTILS_H
#define MY_UTILS_H 

#include <iostream>
#include <string>
#include <algorithm>

enum CipherType
{
	DESType,
	RSAType,
	UnknownType
};

enum DESMode
{
	ECB,
	CBC,
	CFB,
	UnknownMode
};

enum CipherAction
{
	ENC,
	DEC,
	UnknownAction
};

/**
 * Get the type of cipher supplied by the user.
 * @param  arg 	- the argument supplied by the user.
 * @return type - the type of cipher.
 */
CipherType getCipherType(std::string );

/**
 * Get the DES cipher block mode supplied by the user.
 * @param  arg 	- the argument supplied by the user.
 * @return mode - the mode of encryption / decryption.
 */
DESMode getDESMode(std::string );

/**
 * Get the type of action (encryption or decryption) supplied by the user.
 * @param  arg 		- the argument supplied by the user
 * @return action 	- the corresponding type of action
 */
CipherAction getCipherAction(std::string );


#endif
