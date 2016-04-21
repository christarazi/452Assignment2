#include "CipherInterface.h"
#include "DES.h"
#include "RSA.h"
#include "Utils.h"

using namespace std;

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

	if (argc == 7)
	{
		cType = getCipherType(string(argv[1]));
		action = getCipherAction(string(argv[4]));
	}
	else
	{
		cout << "Usage: DES" << argv[0] << " <CIPHERTYPE> <DESKEY> <MODE> <ENC/DEC> <INPUTFILE> <OUTPUT FILE>\n";
		cout << "Usage: RSA" << argv[0] << " <CIPHERTYPE> <RSAPUBKEYFILE> <RSAPRIVKEYFILE> <ENC/DEC> <INPUTFILE> <OUTPUT FILE>\n";
		cleanExit(NULL, -1);
	}

	// Create an instance of cipher.
	CipherInterface * cipher;

	// Switch on the cipher type.
	switch (cType)
	{
	case DESType:
		cipher = new DES(getDESMode(string(argv[3])));
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
