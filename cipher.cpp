#include <iostream>
#include <string>
#include <algorithm>
#include "CipherInterface.h"
#include "DES.h"
#include "RSA.h"

using namespace std;

enum CipherType
{
	DESType,
	RSAType,
	UnknownType
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
CipherType getCipherType(string arg)
{
	CipherType type;
	transform(arg.begin(), arg.end(), arg.begin(), ::tolower);

	if (arg.compare("des") == 0)
		type = DESType;
	else if (arg.compare("rsa") == 0)
		type = RSAType;
	else
		type = UnknownType;

	return type;
}

/**
 * Get the type of action (encryption or decryption) supplied by the user.
 * @param  arg 		- the argument supplied by the user
 * @return action 	- the corresponding type of action
 */
CipherAction getCipherAction(string arg)
{
	CipherAction action;
	transform(arg.begin(), arg.end(), arg.begin(), ::tolower);

	if (arg.compare("enc") == 0)
		action = ENC;
	else if (arg.compare("dec") == 0)
		action = DEC;
	else
		action = UnknownAction;

	return action;
}

/**
 * Function to perform a clean exit.
 * @param c       - the cipher object to free
 * @param exitVal - the exit value to return
 */
void cleanExit(CipherInterface* c, int exitVal)
{
	delete c;
	exit(exitVal);
}

int main(int argc, char** argv)
{
	CipherType cType = UnknownType;
	CipherAction action = UnknownAction;

	if (argc == 6)
	{
		cType = getCipherType(string(argv[1]));
		action = getCipherAction(string(argv[3]));
	}
	else if (argc == 7)
	{
		// Get the cipher type and the action to be performed.
		cType = getCipherType(string(argv[1]));
		action = getCipherAction(string(argv[4]));
	}
	else
	{
		cout << "Usage: " << argv[0] << " <CIPHERTYPE> <DESKEY> [<RSAPUBKEYFILE> <RSAPRIVKEYFILE>] <ENC/DEC> <INPUTFILE> <OUTPUT FILE>\n";
		cleanExit(NULL, -1);
	}

	// Create an instance of cipher.
	CipherInterface * cipher;

	// Switch on the cipher type.
	switch (cType)
	{
	case DESType:
		cipher = new DES();
		break;
	case RSAType:
		cipher = new RSA_452();
		break;
	case UnknownType:
		cout << "Unknown type\n";
		cleanExit(cipher, -1);
		break;
	default:
		break;
	}

	/* Error checks */
	if (!cipher)
	{
		fprintf(stderr, "ERROR [%s %s %d]: could not allocate memory\n",
		        __FILE__, __FUNCTION__, __LINE__);
		cleanExit(cipher, -1);
	}

	if (cType == DESType)
	{
		/* Set the encryption key
		 * A valid key comprises 16 hexadecimal characters. Below is one example.
		 * Your program should take input from command line.
		 */
		if (!cipher->setKey((unsigned char*) argv[2]))
		{
			cout << "Error: invalid key\n";
			cleanExit(cipher, -1);
		}

		switch (action)
		{
		case ENC:
			// Perform encryption.
			cipher->encrypt((unsigned char*) argv[4], (unsigned char*) argv[5]);
			break;
		case DEC:
			// Perform decryption.
			cipher->decrypt((unsigned char*) argv[4], (unsigned char*) argv[5]);
			break;
		case UnknownAction:
			cout << "Unknown action\n";
			cleanExit(cipher, -1);
			break;
		default:
			break;
		}
	}
	else if (cType == RSAType)
	{
		cipher->setKey((unsigned char*) argv[2], (unsigned char*) argv[3]);

		switch (action)
		{
		case ENC:
			// Perform encryption.
			cipher->encrypt((unsigned char*) argv[5], (unsigned char*) argv[6]);
			break;
		case DEC:
			// Perform decryption.
			cipher->decrypt((unsigned char*) argv[5], (unsigned char*) argv[6]);
			break;
		case UnknownAction:
			cout << "Unknown action\n";
			cleanExit(cipher, -1);
			break;
		default:
			break;
		}
	}
	else
	{
		cout << "Strange error\n";
		cleanExit(cipher, -1);
	}

	delete cipher;

	return 0;
}
