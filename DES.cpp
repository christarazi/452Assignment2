#include "DES.h"

using namespace std;

#define MAX_DES_BYTES 8

/**
 * The default constructor to initialize the initialization vector.
 */
DES::DES(DESMode mode)
{
	this->desMode = mode;
	this->initVec = vector<unsigned char>(MAX_DES_BYTES);
}

/**
 * Sets the key to use
 * @param key 	- the key to use.
 * @return 		- true if the key is valid and false otherwise.
 */
bool DES::setKey(const unsigned char* keyArray, const unsigned char* iv)
{
	/* The key error code */
	int keyErrorCode = -1;

	/* A single byte */
	unsigned char singleByte = 0;

	/* The key index */
	int keyIndex = 0;

	/* The DES key index */
	int desKeyIndex = 0;

	// Check if an IV is provided and if it's empty, only if the mode is not ECB.
	if (this->desMode != ECB && strlen((char*) iv) == 0)
	{
		fprintf(stderr, "\niv is empty %d\n", keyErrorCode);
		return false;
	}

	/* Go through the entire key character by character */
	while (desKeyIndex != MAX_DES_BYTES)
	{
		/* Convert the key if the character is valid */
		if ((this->des_key[desKeyIndex] = twoCharToHexByte(keyArray + keyIndex)) == 'z')
		{
			fprintf(stderr, "\nkey is invalid %d\n", keyErrorCode);
			return false;
		}

		// Only check IV if the mode is not ECB.
		if (this->desMode != ECB)
		{
			/* Convert the IV if the character is valid */
			if ((this->initVec[desKeyIndex] = twoCharToHexByte(iv + keyIndex)) == 'z')
			{
				fprintf(stderr, "\niv is invalid %d\n", keyErrorCode);
				return false;
			}
		}

		/* Go to the second pair of characters */
		keyIndex += 2;

		/* Increment the index */
		++desKeyIndex;
	}

	// Set the key to have odd parity. All DES keys must have odd parity.
	DES_set_odd_parity(&this->des_key);

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
 * @param  padding 	  - the number of pad bytes needed.
 * @return readBuffer - the padded buffer.
 */
vector<unsigned char> DES::padBlock(vector<unsigned char> readBuffer, int padding)
{
	// Get the position at which we must pad.
	int position = MAX_DES_BYTES - padding;

	for (; position < MAX_DES_BYTES; ++position)
		readBuffer[position] = (unsigned char) padding;

	return readBuffer;
}

/**
 * Function to perform DES encryption / decryption based on desAction.
 * @param  block 	  - the block we want to encrypt / decrypt.
 * @param  desAction  - the action to perform.
 * @return desBlock   - the encrypted / decrypted block.
 */
vector<unsigned char> DES::performDES(vector<unsigned char> block, int desAction)
{
	DES_LONG desBlockLong [2];
	vector<unsigned char> desBlock(MAX_DES_BYTES);

	// Convert block to two long integers.
	desBlockLong[0] = ctol(&block.data()[0]);
	desBlockLong[1] = ctol(&block.data()[4]);

	// Perform action.
	DES_encrypt1(desBlockLong, &this->key, desAction);

	// Convert two long integers back to bytes.
	ltoc(desBlockLong[0], &desBlock.data()[0]);
	ltoc(desBlockLong[1], &desBlock.data()[4]);

	return desBlock;
}

/**
 * Function to perform DES in CBC mode.
 * @param  readBlock 	- the input block from the file.
 * @param  cipherBlock  - pass-by-reference vector holding the previous block for chaining.
 * @param  action  		- the action to perform (ENC == 1/ DEC == 0).
 * @param  firstRun  	- indicates where this is first run through CBC or not.
 * @return 				- return new vector based on action.
 */
vector<unsigned char> DES::performCBC(vector<unsigned char> readBlock, vector<unsigned char> &cipherBlock,
                                      bool action, bool &firstRun)
{
	// If we are encrypting then proceed, otherwise we go to the else block.
	if (action)
	{
		DES_LONG cipherBlockLong[2], plaintextBlockLong[2], result[2];

		/**
		 * If this is the first run through, then use the initVec.
		 * Else, use the previous block, which is cipherBlock.
		 */
		if (firstRun)
		{
			cipherBlockLong[0] = ctol(&this->initVec.data()[0]);
			cipherBlockLong[1] = ctol(&this->initVec.data()[4]);
			firstRun = false;
		}
		else
		{
			cipherBlockLong[0] = ctol(&cipherBlock.data()[0]);
			cipherBlockLong[1] = ctol(&cipherBlock.data()[4]);
		}

		// Convert plaintext into long integers.
		plaintextBlockLong[0] = ctol(&readBlock.data()[0]);
		plaintextBlockLong[1] = ctol(&readBlock.data()[4]);

		// Perform XORs between cipher and plaintext.
		result[0] = cipherBlockLong[0] ^ plaintextBlockLong[0];
		result[1] = cipherBlockLong[1] ^ plaintextBlockLong[1];

		// Convert result back to bytes and store in cipherBlock.
		ltoc(result[0], &cipherBlock.data()[0]);
		ltoc(result[1], &cipherBlock.data()[4]);

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

		/**
		 * If this is the first run through, then use the initVec to convert to long integers.
		 * Else, use the previous block, which is cipherBlock, to convert to long integers.
		 */
		if (firstRun)
		{
			cipherBlockLong[0] = ctol(&this->initVec.data()[0]);
			cipherBlockLong[1] = ctol(&this->initVec.data()[4]);
			firstRun = false;
		}
		else
		{
			cipherBlockLong[0] = ctol(&cipherBlock.data()[0]);
			cipherBlockLong[1] = ctol(&cipherBlock.data()[4]);
		}

		// Convert decrypted block to long integers.
		decryptedBlockLong[0] = ctol(&decryptedBlock.data()[0]);
		decryptedBlockLong[1] = ctol(&decryptedBlock.data()[4]);

		// Perform XORs between cipher block and decrypted block.
		result[0] = cipherBlockLong[0] ^ decryptedBlockLong[0];
		result[1] = cipherBlockLong[1] ^ decryptedBlockLong[1];

		// Convert result back to bytes and store in decryptedBlock.
		ltoc(result[0], &decryptedBlock.data()[0]);
		ltoc(result[1], &decryptedBlock.data()[4]);

		// Store the input block in cipherBlock the next step in the chaining process.
		cipherBlock = readBlock;

		return decryptedBlock;
	}
}

/**
 * Function to perform left circular shift.
 * @param  block     	- the 8 byte block to be shifted.
 * @param  c            - the previous byte to insert.
 * @return 				- return shifted vector.
 */    
vector<unsigned char> DES::shiftOneByte(vector<unsigned char> block, unsigned char c)
{
    //Left Circular Shift by 1 byte.
    rotate(block.begin(), block.begin()+1, block.end());
    
    block[block.size()-1] = c;
    return block;
}

/**
 * Function to perform DES in CFB mode.
 * @param  textVec   	- The input buffer 
 * @param  returnVec    - pass-by-reference vector holding the previous block for chaining.
 * @param  action  		- the action to perform (ENC / DEC).
 * @param  firstRun  	- indicates where this is first run through CBC or not.
 * @param  previousByte - The cipher byte resulting from CFB. 
 * @return 				- return new vector based on action.
 */
vector<unsigned char> DES::performCFB(vector<unsigned char> textVec, vector<unsigned char> &returnVec,
                                         bool action, bool &firstRun, unsigned char &previousByte)
{
    //Read 1 byte at a time because we are similating a stream cipher.
    for (int i = 0; i < textVec.size();  ++i)
    {
        //Encrypt Shift Vector
        if(firstRun)
        {
            this->shiftVec = this->initVec;
            firstRun = false;
        }
        else
            this->shiftVec = shiftOneByte(this->shiftVec, previousByte);
        this->shiftVec = performDES(this->shiftVec, 1);
        
        //X-OR First byte in Shift Vector with the Input Byte
        returnVec[i] = (unsigned char)(textVec[i] ^ shiftVec[0]);
        
        //Set the cipher byte for the next iteration.
        if (action)
            previousByte = returnVec[i];
        else
            previousByte = textVec[i];
    }
    return returnVec;
}

/**
 * Encrypt the file at plaintextFileIn and output at ciphertextFileOut.
 * @param  plaintextFileIn   - the file to encrypt.
 * @param  ciphertextFileOut - the encrypted output file.
 * @return 					 - true if successful, false otherwise.
 */
bool DES::encrypt(const unsigned char* plaintextFileIn, const unsigned char* ciphertextFileOut)
{
	bool ecb = false, cbc = false, cfb = false, isFirstRun = true;

	// Set the appropriate mode of encryption.
	switch (this->desMode)
	{
	case ECB: ecb = true; break;
	case CBC: cbc = true; break;
	case CFB: cfb = true; break;
	case UnknownMode:
		cerr << "Error in encryption: unknown mode detected\n";
		return false;
	default:
		cerr << "Error in decryption: could not read mode\n";
		return false;
	}

	// Open files in binary mode.
	fstream fIn((char*) plaintextFileIn, ios::in | ios::binary);
	fstream fOut((char*) ciphertextFileOut, ios::out | ios::binary);

	/**
	 * readBuffer must be of size 8 because that's the
	 * 	maximum number of bytes DES takes in for encryption.
	 * 	encryptedBuffer is of size 8 because that's the number of bytes DES outputs.
	 */
	vector<unsigned char> readBuffer(MAX_DES_BYTES);
	vector<unsigned char> encryptedBuffer(MAX_DES_BYTES);
	vector<unsigned char> cipherBuffer(MAX_DES_BYTES);

	// Fill the buffers with zeros.
	fill(readBuffer.begin(), readBuffer.end(), 0);
	fill(encryptedBuffer.begin(), encryptedBuffer.end(), 0);
	fill(cipherBuffer.begin(), cipherBuffer.end(), 0);

	int totalBytesRead = 0;
	int totalBytesWritten = 0;
	unsigned char numPadBytes[1];
    unsigned char previousByte;  //The previous Cipher byte used in DES, CFB Mode.  

	// Make sure both file streams were able to open the files.
	if (fIn.is_open() && fOut.is_open())
	{
		// stat() call initializes fileStat with the file attributes.
		if (stat((char*) plaintextFileIn, &this->fileStat) == -1)
		{
			perror("stat");
			return false;
		}

		// Get the file size.
		uint64_t fileSize = (uint64_t) this->fileStat.st_size;

		// Number of pad bytes is MAX_DES_BYTES - (fileSize % MAX_DES_BYTES).
		if ((fileSize % MAX_DES_BYTES) == 0)
			numPadBytes[0] = 0;
		else
			numPadBytes[0] = MAX_DES_BYTES - (fileSize % MAX_DES_BYTES);

		// Write number of pad bytes at the beginning of the file.
		fOut.write((char*) numPadBytes, 1);

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

			/**
			 * We only need to pad the last block, so we check if we're at EOF.
			 *
			 * Note: .peek() looks at the next character in the fstream
			 * without extracting it (advancing the pointer), however, if the
			 * next character is EOF, then the EOF bit will be triggered,
			 * which technically advances the pointer.
			 */
			if (fIn.peek() == EOF)
				readBuffer = padBlock(readBuffer, (int) numPadBytes[0]);

			/**
			 * Check which mode we are using.
			 * 1 means encryption, 0 means decryption.
			 */
			if (ecb)
				encryptedBuffer = performDES(readBuffer, 1);
			else if (cbc)
				encryptedBuffer = performCBC(readBuffer, cipherBuffer, 1, isFirstRun);
			else if (cfb)
                encryptedBuffer = performCFB(readBuffer, cipherBuffer, 1, isFirstRun, previousByte);
            else
				return false;

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
		return false;
	}

	return true;
}

/**
 * Decrypt the file at ciphertextFileIn and output at plaintextFileOut.
 * @param  ciphertextFileIn - the file to decrypt.
 * @param  plaintextFileOut - the decrypted output file.
 * @return                  - true if successful, false otherwise.
 */
bool DES::decrypt(const unsigned char* plaintextFileIn, const unsigned char* ciphertextFileOut)
{
	bool ecb = false, cbc = false, cfb = false, isFirstRun = true;

	// Set the appropriate mode of decryption.
	switch (this->desMode)
	{
	case ECB: ecb = true; break;
	case CBC: cbc = true; break;
	case CFB: cfb = true; break;
	case UnknownMode:
		cerr << "Error in decryption: unknown mode detected\n";
		return false;
	default:
		cerr << "Error in decryption: could not read mode\n";
		return false;
	}

	// Open files in binary mode.
	fstream fIn((char*) plaintextFileIn, ios::in | ios::binary);
	fstream fOut((char*) ciphertextFileOut, ios::out | ios::binary);

	/**
	 * readBuffer must be of size 8 because that's the
	 * 	maximum number of bytes DES takes in for encryption.
	 * 	encryptedBuffer is of size 8 because that's the number of bytes DES outputs.
	 */
	vector<unsigned char> readBuffer(MAX_DES_BYTES);
	vector<unsigned char> decryptedBuffer(MAX_DES_BYTES);
	vector<unsigned char> cipherBuffer(MAX_DES_BYTES);

	// Fill the buffers with zeros.
	fill(readBuffer.begin(), readBuffer.end(), 0);
	fill(decryptedBuffer.begin(), decryptedBuffer.end(), 0);
	fill(cipherBuffer.begin(), cipherBuffer.end(), 0);

	int totalBytesRead = 0;
	int totalBytesWritten = 0;
	int padBytes;
	unsigned char numPadBytes[1];
    unsigned char previousByte;  //The previous Cipher byte used in DES, CFB Mode.  

	// Make sure both file streams were able to open the files.
	if (fIn.is_open() && fOut.is_open())
	{
		// Read the pad byte from the file.
		fIn.read((char*) numPadBytes, 1);

		// Loop while there is still data to be read from the file.
		while (fIn.good())
		{
			/**
			 * Read the max number of bytes (which is 8 here)
			 * and store it in the readBuffer.
			 */
			fIn.read((char*) readBuffer.data(), MAX_DES_BYTES);
			int bytesRead = fIn.gcount();

			/**
			 * Check which mode we are using.
			 * 1 means encryption, 0 means decryption.
			 */
			if (ecb)
				decryptedBuffer = performDES(readBuffer, 0);
			else if (cbc)
				decryptedBuffer = performCBC(readBuffer, cipherBuffer, 0, isFirstRun);
			else if (cfb)
                decryptedBuffer = performCFB(readBuffer, cipherBuffer, 0, isFirstRun, previousByte);
            else
				return false;

			/**
			 * Note: .peek() looks at the next character in the fstream
			 * without extracting it (advancing the pointer), however, if the
			 * next character is EOF, then the EOF bit will be triggered,
			 * which technically advances the pointer.
			 *
			 * If next byte is EOF, set padBytes to number of bytes.
			 * Else padBytes is 0.
			 */
			fIn.peek() == EOF ? padBytes = numPadBytes[0] : padBytes = 0;

			copy(begin(decryptedBuffer), end(decryptedBuffer) - padBytes,
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

	return true;
}

/**
 * Converts an array of 8 characters to longs.
 * (i.e. 4 bytes/32 bits)
 * @param c 	- the array of 4 characters (i.e. 1-byte per/character)
 * @return 		- the long integer (32 bits) where each byte is equivalent
 *             		to one of the bytes in a character array
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
 * @return 			- the converted character, or 'z' on error
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
 * Converts two characters into a hex integers and then inserts
 * the integers into the higher and lower bits of the byte
 * @param twoChars 	- two characters representing the hexadecimal nibbles of the byte.
 * @return 			- the byte containing having the value of two
 *              	characters e.g. string "ab" becomes hexadecimal integer 0xab.
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

