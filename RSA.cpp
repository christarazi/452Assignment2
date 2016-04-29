#include "RSA.h"

using namespace std;

#define MOD_SIZE 2048
#define ENC_READ_MAX 215
#define DEC_READ_MAX 256
#define WRITE_MAX 256

/**
 * NOTE: This is used for RSA.
 * Sets the key pair to use.
 * @param  publicKeyFile  - the file containing the public key.
 * @param  privateKeyFile - the file containing the private key.
 * @return                - true if setting key succeeded; false otherwise.
 */
bool RSA_452::setKey(const unsigned char* publicKeyFile, const unsigned char* privateKeyFile)
{
	FILE* fPublic;
	FILE* fPrivate;

	fPublic = fopen((char*) publicKeyFile, "r");
	fPrivate = fopen((char*) privateKeyFile, "r");

	if (!fPublic)
	{
		perror("fopen");
		return false;
	}

	if (!fPrivate)
	{
		perror("fopen");
		return false;
	}

	// Set the public and private key.
	this->pubKey = PEM_read_RSA_PUBKEY(fPublic, NULL, NULL, NULL);
	this->privKey = PEM_read_RSAPrivateKey(fPrivate, NULL, NULL, NULL);

	fclose(fPublic);
	fclose(fPrivate);

	return true;
}

/**
 * Encrypt the file at plaintextFileIn and output at ciphertextFileOut.
 * @param  plaintextFileIn   - the file to encrypt.
 * @param  ciphertextFileOut - the encrypted output file.
 * @return 					 - true if successful, false otherwise.
 */
bool RSA_452::encrypt(const unsigned char* plaintextFileIn,
                      const unsigned char* ciphertextFileOut)
{
	// Open files in binary mode.
	fstream fIn((char*) plaintextFileIn, ios::in | ios::binary);
	fstream fOut((char*) ciphertextFileOut, ios::out | ios::binary);

	/**
	 * readBuffer must be of size 215 because that's the maximum number of
	 * bytes RSA takes in for encryption (because of padding).
	 * writeBuffer is of size 256 because that's the number of bytes RSA outputs.
	 */
	vector<unsigned char> readBuffer(ENC_READ_MAX);
	vector<unsigned char> writeBuffer(WRITE_MAX);

	// Fill the buffers with zeros.
	fill(readBuffer.begin(), readBuffer.end(), 0);
	fill(writeBuffer.begin(), writeBuffer.end(), 0);

	// The buffer containing the error message .
	char errorBuff[130];

	int totalBytesRead = 0;
	int totalBytesWritten = 0;
	int encryptedBytes = 0;

	// Make sure both file streams were able to open the files.
	if (fIn.is_open() && fOut.is_open())
	{
		// Loop while there is still data to be read from the file.
		while (fIn.good())
		{
			/**
			 * Read the max number of bytes (which is 214 here)
			 * and store it in the readBuffer.
			 */
			fIn.read((char*) readBuffer.data(), ENC_READ_MAX - 1);
			int bytesRead = fIn.gcount();

			// Break if we didn't read any bytes.
			if (bytesRead == 0)
				break;

			// Perform encryption on the block we just read and store it in writeBuffer.
			if ((encryptedBytes = RSA_public_encrypt(bytesRead, readBuffer.data(),
			                      writeBuffer.data(), pubKey, RSA_PKCS1_OAEP_PADDING)) < 0)
			{
				ERR_load_crypto_strings();
				ERR_error_string(ERR_get_error(), errorBuff);
				fprintf(stderr, "Error encrypting message: %s\n", errorBuff);
			}

			totalBytesWritten += encryptedBytes;
			totalBytesRead += bytesRead;

			// Fancy C++11 function to copy writeBuffer to output file.
			copy(begin(writeBuffer), end(writeBuffer),
			     ostream_iterator<unsigned char>(fOut, ""));
		}
	}
	else
	{
		perror("is_open");
		fIn.close();
		fOut.close();
		return false;
	}

	fIn.close();
	fOut.close();

	return true;
}

/**
 * Decrypt the file at ciphertextFileIn and output at plaintextFileOut.
 * @param  ciphertextFileIn - the file to decrypt.
 * @param  plaintextFileOut - the decrypted output file.
 * @return                  - true if successful, false otherwise.
 */
bool RSA_452::decrypt(const unsigned char* ciphertextFileIn,
                      const unsigned char* plaintextFileOut)
{
	// Open files in binary mode.
	fstream fIn((char*) ciphertextFileIn, ios::in | ios::binary);
	fstream fOut((char*) plaintextFileOut, ios::out | ios::binary);

	/**
	 * readBuffer must be of size 256 because that's the maximum number of
	 * bytes RSA takes in for encryption (because of padding).
	 * writeBuffer is of size 256 because that's the number of bytes RSA outputs.
	 */
	vector<unsigned char> readBuffer(DEC_READ_MAX);
	vector<unsigned char> writeBuffer(WRITE_MAX);

	// Fill the buffers with zeros.
	fill(readBuffer.begin(), readBuffer.end(), 0);
	fill(writeBuffer.begin(), writeBuffer.end(), 0);

	// The buffer containing the error message .
	char errorBuff[130];

	int totalBytesRead = 0;
	int totalBytesWritten = 0;
	int decryptedBytes = 0;

	// Make sure both file streams were able to open the files.
	if (fIn.is_open() && fOut.is_open())
	{
		// Loop while there is still data to be read from the file.
		while (fIn.good())
		{
			/**
			 * Read the max number of bytes (which is 214 here)
			 * and store it in the readBuffer.
			 */
			fIn.read((char*) readBuffer.data(), DEC_READ_MAX);
			int bytesRead = fIn.gcount();

			// Break if we didn't read any bytes.
			if (bytesRead == 0)
				break;

			// Perform encryption on the block we just read and store it in writeBuffer.
			if ((decryptedBytes = RSA_private_decrypt(bytesRead, readBuffer.data(),
			                      writeBuffer.data(), privKey, RSA_PKCS1_OAEP_PADDING)) < 0)
			{
				ERR_load_crypto_strings();
				ERR_error_string(ERR_get_error(), errorBuff);
				fprintf(stderr, "Error decrypting message: %s\n", errorBuff);
			}

			totalBytesWritten += decryptedBytes;
			totalBytesRead += bytesRead;

			// Fancy C++11 function to copy writeBuffer to output file.
			copy(begin(writeBuffer), begin(writeBuffer) + decryptedBytes,
			     ostream_iterator<unsigned char>(fOut, ""));
		}
	}
	else
	{
		perror("is_open");
		fIn.close();
		fOut.close();
		return false;
	}

	fIn.close();
	fOut.close();

	return true;
}

/**
 * Define destructor to free the RSA keys from memory.
 */
RSA_452::~RSA_452()
{
	RSA_free(this->pubKey);
	RSA_free(this->privKey);
}