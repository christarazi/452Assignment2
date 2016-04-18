#include "DES.h"
#include <iostream>

using namespace std;

#define MAX_DES_BYTES 8

/**
 * Sets the key to use
 * @param key - the key to use
 * @return - True if the key is valid and False otherwise
 */
bool DES::setKey(const unsigned char* keyArray)
{
	/* The key error code */
	int keyErrorCode = -1;

	/* A single byte */
	unsigned char singleByte = 0;

	/* The key index */
	int keyIndex = 0;

	/* The DES key index */
	int desKeyIndex = 0;

	/* Go through the entire key character by character */
	while (desKeyIndex != 8)
	{
		/* Convert the key if the character is valid */
		if ((this->des_key[desKeyIndex] = twoCharToHexByte(keyArray + keyIndex)) == 'z')
			return false;

		/* Go to the second pair of characters */
		keyIndex += 2;

		/* Increment the index */
		++desKeyIndex;
	}

	//fprintf(stdout, "DES KEY: ");

	DES_set_odd_parity(&this->des_key);

	/* Print the key */
	// for (keyIndex = 0; keyIndex < 8; ++keyIndex)
	// 	fprintf(stdout, "%02x", this->des_key[keyIndex]);

	//fprintf(stdout, "\n");

	/* Set the encryption key */
	if ((keyErrorCode = des_set_key_checked(&this->des_key, this->key)) != 0)
	{
		fprintf(stderr, "\nkey error %d\n", keyErrorCode);

		return false;
	}

	/* All is well */
	return true;
}

/**
 * Function to pad a DES block if necessary.
 * @param  readBuffer - the block we want to verify padding for.
 * @param  bytesRead  - the number of we've read from the file.
 * @return readBuffer - the padded buffer.
 */
vector<unsigned char> DES::verifyPadding(vector<unsigned char> readBuffer, int bytesRead)
{
	int padding, position;

	// If bytesRead is not equal to MAX_DES_BYTES, then we need to pad readBuffer.
	if (bytesRead != MAX_DES_BYTES)
	{
		// Number of pad bytes needed.
		padding = MAX_DES_BYTES - bytesRead;

		// Starting position to insert pad bytes.
		position = MAX_DES_BYTES - padding;
		//cout << "This block requires " << padding << " pads.\n";

		// Loop until we fill up the entire block.
		// Filling readBuffer with number of pad bytes as the padding.
		while (position < MAX_DES_BYTES)
		{
			readBuffer[position] = padding;
			position += 1;
		}
	}

	return readBuffer;
}

/**
 * Function to perform DES encryption / decryption based on desAction.
 * @param  readBuffer - the block we want to encrypt / decrypt.
 * @param  desAction  - the action to perform.
 * @return desBlock   - the encrypted / decrypted block.
 */
vector<unsigned char> DES::performDES(vector<unsigned char> readBuffer, int desAction)
{
	if (readBuffer.size() != MAX_DES_BYTES)
		cout << "Invalid Plaintext Length:  The length of plaintext must be 8." << endl;

	DES_LONG myBlock [2];
	vector<unsigned char> desBlock(MAX_DES_BYTES);

	// Convert block to two long integers.
	myBlock[0] = ctol(& readBuffer.data()[0]);
	myBlock[1] = ctol(& readBuffer.data()[4]);

	// Perform action.
	DES_encrypt1(myBlock, & this->key, desAction);

	// Convert two long integers back to bytes.
	ltoc(myBlock[0], & desBlock.data()[0]);
	ltoc(myBlock[1], & desBlock.data()[4]);

	return desBlock;
}

/**
 * Function to perform DES in CBC mode.
 * @param  readBlock 	- the ibput block from the file.
 * @param  cipherBlock  - pass-by-reference vector holding the previous block for chaining.
 * @param  initVec  	- the initialization vector.
 * @param  action  		- the action to perform (ENC == 1/ DEC == 0).
 * @param  firstRun  	- indicates where this is first run through CBC or not.
 * @return 				- return new vector based on action.
 */
vector<unsigned char> DES::performCBC(vector<unsigned char> readBlock, vector<unsigned char> & cipherBlock,
                                      vector<unsigned char> initVec, bool action, bool & firstRun)
{
	// If we are encrypting then proceed, otherwise we go to the else block.
	if (action)
	{
		DES_LONG cipherBlockLong[2], plaintextBlockLong[2], result[2];

		// If this is the first run through, then use the initVec.
		// Else, use the previous block, which is cipherBlock.
		if (firstRun)
		{
			cipherBlockLong[0] = ctol(& initVec.data()[0]);
			cipherBlockLong[1] = ctol(& initVec.data()[4]);
			firstRun = false;
		}
		else
		{
			cipherBlockLong[0] = ctol(& cipherBlock.data()[0]);
			cipherBlockLong[1] = ctol(& cipherBlock.data()[4]);
		}

		// Convert plaintext into long integers.
		plaintextBlockLong[0] = ctol(& readBlock.data()[0]);
		plaintextBlockLong[1] = ctol(& readBlock.data()[4]);

		// Perform XORs between cipher and plaintext.
		result[0] = cipherBlockLong[0] ^ plaintextBlockLong[0];
		result[1] = cipherBlockLong[1] ^ plaintextBlockLong[1];

		// Convert result back to bytes and store in cipherBlock.
		ltoc(result[0], & cipherBlock.data()[0]);
		ltoc(result[1], & cipherBlock.data()[4]);

		// Perform encryption on the cipherBlock.
		vector<unsigned char> encryptedBuffer = performDES(cipherBlock, 1);  //1 for encrypting

		// Store the output of the encryption for the next step in the chaining process.
		cipherBlock = encryptedBuffer;

		return encryptedBuffer;
	}
	else
	{
		DES_LONG cipherBlockLong[2], decryptedBlockLong[2], result[2];

		// Perform decryption on the input block.
		vector<unsigned char> decryptedBlock = performDES(readBlock, 0);  //0 for decrypting
		
		// If this is the first run through, then use the initVec to convert to long integers.
		// Else, use the previous block, which is cipherBlock, to convert to long integers.
		if (firstRun)
		{
			cipherBlockLong[0] = ctol(& initVec.data()[0]);
			cipherBlockLong[1] = ctol(& initVec.data()[4]);

			firstRun = false;
		}
		else
		{
			cipherBlockLong[0] = ctol(& cipherBlock.data()[0]);
			cipherBlockLong[1] = ctol(& cipherBlock.data()[4]);
		}

		// Convert decrypted block to long integers.
		decryptedBlockLong[0] = ctol(& decryptedBlock.data()[0]);
		decryptedBlockLong[1] = ctol(& decryptedBlock.data()[4]);

		// Perform XORs between cipher block and decrypted block.
		result[0] = cipherBlockLong[0] ^ decryptedBlockLong[0];
		result[1] = cipherBlockLong[1] ^ decryptedBlockLong[1];

		// Convert result back to bytes and store in decryptedBlock.
		ltoc(result[0], & decryptedBlock.data()[0]);
		ltoc(result[1], & decryptedBlock.data()[4]);

		// Store the input block in cipherBlock the next step in the chaining process.
		cipherBlock = readBlock;

		return decryptedBlock;
	}
}

/**
 * Encrypt the file at plaintextFileIn and output at ciphertextFileOut.
 * @param  plaintextFileIn   - the file to encrypt.
 * @param  ciphertextFileOut - the encrypted output file.
 * @return 					 - void
 */
void DES::encrypt(const unsigned char* plaintextFileIn, const unsigned char* ciphertextFileOut)
{
	bool doCBC = true, isFirstRun = true;

	// Open files in binary mode.
	fstream fIn((char*) plaintextFileIn, ios::in | ios::binary);
	fstream fOut((char*) ciphertextFileOut, ios::out | ios::binary);

	// readBuffer must be of size 8 because that's the
	// maximum number of bytes DES takes in for encryption.
	// encryptedBuffer is of size 8 because that's the number of bytes DES outputs.
	vector<unsigned char> readBuffer(MAX_DES_BYTES);
	vector<unsigned char> encryptedBuffer(MAX_DES_BYTES);
	vector<unsigned char> cipherBuffer(MAX_DES_BYTES);
	vector<unsigned char> initializationVec(MAX_DES_BYTES);

	// Fill the buffers with zeros.
	fill(readBuffer.begin(), readBuffer.end(), 0);
	fill(encryptedBuffer.begin(), encryptedBuffer.end(), 0);
	fill(cipherBuffer.begin(), cipherBuffer.end(), 0);
	fill(initializationVec.begin(), initializationVec.end(), 1);

	int totalBytesRead = 0;
	int totalBytesWritten = 0;
	int encryptedBytes = 0;

	// Make sure both file streams were able to open the files.
	if (fIn.is_open() && fOut.is_open())
	{
		// Loop while there is still data to be read from the file.
		while (fIn.good())
		{
			// Read the max number of bytes (which is 8 here)
			// and store it in the readBuffer.
			fIn.read((char*) readBuffer.data(), MAX_DES_BYTES);
			int bytesRead = fIn.gcount();

			// Break if we didn't read any bytes.
			if (bytesRead == 0)
				break;

			// Make sure the block is padded if necessary.
			readBuffer = verifyPadding(readBuffer, bytesRead);

			// Check if we are doing CBC. Else perform normal DES encryption.
			if (doCBC)
			{
				if (isFirstRun)
					encryptedBuffer = performCBC(readBuffer, cipherBuffer, initializationVec, 1, isFirstRun);
				else
					encryptedBuffer = performCBC(readBuffer, cipherBuffer, initializationVec, 1, isFirstRun);
			}
			else
				encryptedBuffer = performDES(readBuffer, 1);

			// Fancy C++11 function to copy encryptedBuffer to output file.
			copy(begin(encryptedBuffer), end(encryptedBuffer),
			     ostream_iterator<unsigned char>(fOut, ""));
		}
	}
	else
	{
		perror("is_open");
		fIn.close();
		fOut.close();
		exit(-1);
	}
}

/**
 * Decrypt the file at ciphertextFileIn and output at plaintextFileOut.
 * @param  ciphertextFileIn - the file to decrypt.
 * @param  plaintextFileOut - the decrypted output file.
 * @return                  - void
 */
void DES::decrypt(const unsigned char* plaintextFileIn, const unsigned char* ciphertextFileOut)
{
	bool doCBC = true, isFirstRun = true;

	// Open files in binary mode.
	fstream fIn((char*) plaintextFileIn, ios::in | ios::binary);
	fstream fOut((char*) ciphertextFileOut, ios::out | ios::binary);

	// readBuffer must be of size 215 because that's the maximum number of
	// bytes RSA takes in for encryption (because of padding).
	// decryptedBuffer is of size 256 because that's the number of bytes RSA outputs.
	vector<unsigned char> readBuffer(MAX_DES_BYTES);
	vector<unsigned char> decryptedBuffer(MAX_DES_BYTES);
	vector<unsigned char> cipherBuffer(MAX_DES_BYTES);
	vector<unsigned char> initializationVec(MAX_DES_BYTES);

	// Fill the buffers with zeros.
	fill(readBuffer.begin(), readBuffer.end(), 0);
	fill(decryptedBuffer.begin(), decryptedBuffer.end(), 0);
	fill(cipherBuffer.begin(), cipherBuffer.end(), 0);
	fill(initializationVec.begin(), initializationVec.end(), 1);

	int totalBytesRead = 0;
	int totalBytesWritten = 0;
	int encryptedBytes = 0;

	// Make sure both file streams were able to open the files.
	if (fIn.is_open() && fOut.is_open())
	{
		// Loop while there is still data to be read from the file.
		while (fIn.good())
		{
			// Read the max number of bytes (which is 8 here)
			// and store it in the readBuffer.
			fIn.read((char*) readBuffer.data(), MAX_DES_BYTES);
			int bytesRead = fIn.gcount();

			// Break if we didn't read any bytes.
			if (bytesRead == 0)
				break;

			// Check if we are doing CBC. Else perform normal DES decryption.
			if (doCBC)
			{
				if (isFirstRun)
					decryptedBuffer = performCBC(readBuffer, cipherBuffer, initializationVec, 0, isFirstRun);
				else
					decryptedBuffer = performCBC(readBuffer, cipherBuffer, initializationVec, 0, isFirstRun);
			}
			else
				decryptedBuffer = performDES(readBuffer, 0);

			// Detect pad bytes and remove them.
			int padBytes = (int) decryptedBuffer[MAX_DES_BYTES - 1];
			if (padBytes >= 1 && padBytes <= 7)
			{
				//cout << "Detected padding: " << padBytes << " bytes\n";
				// Start from the second to last element in decryptedBuffer.
				// Make sure there's padBytes amount of padding.
				// If not, then we did not detect padding.
				for (unsigned int i = 0; i < padBytes; ++i)
				{
					//printf("Checking if decryptedBuffer[%u] is %02x\n", MAX_DES_BYTES - i - 1, (unsigned char) padBytes);
					if (decryptedBuffer[MAX_DES_BYTES - i - 1] != padBytes)
					{
						padBytes = 0;
						break;
					}
					// else
					// 	cout << "Found pad byte\n";
				}
			}
			else
				padBytes = 0;

			// if (padBytes != 0)
			// {
			// 	cout << "Trimming " << padBytes << " bytes\n\n";
			// }

			// Fancy C++11 function to copy decryptedBuffer to output file.
			copy(begin(decryptedBuffer), end(decryptedBuffer) - padBytes,
			     ostream_iterator<unsigned char>(fOut, ""));
		}
	}
	else
	{
		perror("is_open");
		fIn.close();
		fOut.close();
		exit(-1);
	}
}

/**
 * Converts an array of 8 characters
 * (i.e. 4 bytes/32 bits)
 * @param c - the array of 4 characters (i.e. 1-byte per/character
 * @return - the long integer (32 bits) where each byte
 * is equivalent to one of the bytes in a character array
 */
DES_LONG DES::ctol(unsigned char *c)
{
	/* The long integer */
	DES_LONG l;

	l = ((DES_LONG)(*((c)++)));
	l = l | (((DES_LONG)(*((c)++))) << 8L);
	l = l | (((DES_LONG)(*((c)++))) << 16L);
	l = l | (((DES_LONG)(*((c)++))) << 24L);
	return l;
};


/**
 * Converts a long integer (4 bytes = 32 bits)
 * into an array of 8 characters.
 * @param l - the long integer to convert
 * @param c - the character array to store the result
 */
void DES::ltoc(DES_LONG l, unsigned char *c)
{
	*((c)++) = (unsigned char)(l & 0xff);
	*((c)++) = (unsigned char)(((l) >> 8L) & 0xff);
	*((c)++) = (unsigned char)(((l) >> 16L) & 0xff);
	*((c)++) = (unsigned char)(((l) >> 24L) & 0xff);
}

/**
 * Converts a character into a hexadecimal integer
 * @param character - the character to convert
 * @return - the converted character, or 'z' on error
 */
unsigned char DES::charToHex(const char& character)
{
	/* Is the first digit 0-9 ? */
	if (character >= '0' && character <= '9')
		/* Convert the character to hex */
		return character - '0';
	/* It the first digit a letter 'a' - 'f'? */
	else if (character >= 'a' && character <= 'f')
		/* Convert the character to hex */
		return (character - 97) + 10;
	/* Invalid character */
	else return 'z';
}

/**
 * Converts two characters into a hex integers
 * and then inserts the integers into the higher
 * and lower bits of the byte
 * @param twoChars - two characters representing the
 * the hexadecimal nibbles of the byte.
 * @param twoChars - the two characters
 * @return - the byte containing having the
 * valud of two characters e.g. string "ab"
 * becomes hexadecimal integer 0xab.
 */
unsigned char DES::twoCharToHexByte(const unsigned char* twoChars)
{
	/* The byte */
	unsigned char singleByte;

	/* The second character */
	unsigned char secondChar;

	/* Convert the first character */
	if ((singleByte = charToHex(twoChars[0])) == 'z')
	{
		/* Invalid digit */
		return 'z';
	}

	/* Move the newly inserted nibble from the
	 * lower to upper nibble.
	 */
	singleByte = (singleByte << 4);

	/* Conver the second character */
	if ((secondChar = charToHex(twoChars[1])) == 'z')
		return 'z';

	/* Insert the second value into the lower nibble */
	singleByte |= secondChar;

	return singleByte;
}

