#include "DES.h"
#include <iostream>

/**
 * Sets the key to use
 * @param key - the key to use
 * @return - True if the key is valid and False otherwise
 */
bool DES_452::setKey(const unsigned char* keyArray)
{
	/**
	 * First let's covert the char string
	 * into an integer byte string
	 */


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

	fprintf(stdout, "DES KEY: ");

	/* Print the key */
	for (keyIndex = 0; keyIndex < 8; ++keyIndex)
		fprintf(stdout, "%x", this->des_key[keyIndex]);

	fprintf(stdout, "\n");


	/* Set the encryption key */
	if ((keyErrorCode = des_set_key_checked(&des_key, this->key)) != 0)
	{
		fprintf(stderr, "\nkey error %d\n", keyErrorCode);

		return false;
	}

	/* All is well */
	return true;
}

vector <unsigned char> verifyPadding(vector <unsigned char>readBuffer, int bytesRead)
{
    int padding;
    if (bytesRead != 8)
    {
        int position = 0;
        padding = 8 - bytesRead;
        while (position < readBuffer.size())
        {
            if (position < 7)
            {
                readBuffer[position] = '0';
            }
            else
            {
                readBuffer[position] = (char) ((char) padding - '0');
                //readBuffer[position] = getCharEquivilant(padding);
            }
            position += 1;
        }
    }
    return readBuffer;
}

vector <unsigned char> DES_452::performDES(vector <unsigned char> readBuffer, int desAction)
{
    if (readBuffer.size() != 8)
    {
        cout << "Invalid Plaintext Length:  The length of plaintext must be 8." << endl;
    }
    DES_LONG myBlock [2];
    //unsigned char txtText[8];
    vector<unsigned char> txtText(8);
    
    myBlock[0] = ctol(& readBuffer.data()[0]);
    cout << myBlock[0] << endl;
    myBlock[1] = ctol(& readBuffer.data()[4]);
    cout << myBlock[1] << endl;
    
    DES_encrypt1(myBlock, & this->key, desAction);
    
    ltoc(myBlock[0], & txtText.data()[0]);
    ltoc(myBlock[1], & txtText.data()[4]);
    
    
    //for (int i = 0; i < sizeof(txtText); ++i)
    //    cout << txtText[i];
    
    return txtText;
}
/**
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
void DES_452::encrypt(const unsigned char* plaintextFileIn, const unsigned char* ciphertextFileOut)
{
    
    // Open files in binary mode.
    fstream fIn((char*) plaintextFileIn, ios::in | ios::binary);
    fstream fOut((char*) ciphertextFileOut, ios::out | ios::binary);
    
    // readBuffer must be of size 215 because that's the maximum number of
    // bytes RSA takes in for encryption (because of padding).
    // writeBuffer is of size 256 because that's the number of bytes RSA outputs.
    vector<unsigned char> readBuffer(8);
    vector<unsigned char> writeBuffer(8);
    
    // Fill the buffers with zeros.
    fill(readBuffer.begin(), readBuffer.end(), 0);
    fill(writeBuffer.begin(), writeBuffer.end(), 0);
    
    
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
            fIn.read((char*) readBuffer.data(), 8);
            int bytesRead = fIn.gcount();
            
            // Break if we didn't read any bytes.
            if (bytesRead == 0)
                break;
            
            verifyPadding(readBuffer, bytesRead);
            
            writeBuffer = performDES(readBuffer, 1);  //1 for encrypting
            
            // Fancy C++11 function to copy writeBuffer to output file.
            copy(begin(writeBuffer), end(writeBuffer),
                 ostream_iterator<unsigned char>(fOut, ""));
        }
    }
}
        
    
	//LOGIC:
	//1. Check to make sure that the block is exactly 8 characters (i.e. 64 bits)
	//2. Declare an array DES_LONG block[2];
	//3. Use ctol() to convert the first 4 chars into long; store the result in block[0]
	//4. Use ctol() to convert the second 4 chars into long; store the resul in block[1]
	//5. Perform des_encrypt1 in order to encrypt the block using this->key (see sample codes for details)
	//6. Convert the first ciphertext long to 4 characters using ltoc()
	//7. Convert the second ciphertext long to 4 characters using ltoc()
	//8. Save the results in the the dynamically allocated char array
	// (e.g. unsigned char* bytes = new unsigned char[8]).
	//9. Return the pointer to the dynamically allocated array.

/**
 * Decrypts a string of ciphertext
 * @param ciphertext - the ciphertext
 * @return - the plaintext
 */
void DES_452::decrypt(const unsigned char* plaintextFileIn, const unsigned char* ciphertextFileOut)
{
    // Open files in binary mode.
    fstream fIn((char*) plaintextFileIn, ios::in | ios::binary);
    fstream fOut((char*) ciphertextFileOut, ios::out | ios::binary);
    
    // readBuffer must be of size 215 because that's the maximum number of
    // bytes RSA takes in for encryption (because of padding).
    // writeBuffer is of size 256 because that's the number of bytes RSA outputs.
    vector<unsigned char> readBuffer(8);
    vector<unsigned char> writeBuffer(8);
    
    // Fill the buffers with zeros.
    fill(readBuffer.begin(), readBuffer.end(), 0);
    fill(writeBuffer.begin(), writeBuffer.end(), 0);
    
    
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
            fIn.read((char*) readBuffer.data(), 8);
            int bytesRead = fIn.gcount();
            
            // Break if we didn't read any bytes.
            if (bytesRead == 0)
                break;
            
            verifyPadding(readBuffer, bytesRead);
            
            writeBuffer = performDES(readBuffer, 0);  //0 for decrypting
            
            // Fancy C++11 function to copy writeBuffer to output file.
            copy(begin(writeBuffer), end(writeBuffer),
                 ostream_iterator<unsigned char>(fOut, ""));
        }
    }
    
    //LOGIC:
	// Same logic as encrypt(), except in step 5. decrypt instead of encrypting

}

/**
 * Converts an array of 8 characters
 * (i.e. 4 bytes/32 bits)
 * @param c - the array of 4 characters (i.e. 1-byte per/character
 * @return - the long integer (32 bits) where each byte
 * is equivalent to one of the bytes in a character array
 */
DES_LONG DES_452::ctol(unsigned char *c)
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
void DES_452::ltoc(DES_LONG l, unsigned char *c)
{
	*((c)++) = (unsigned char)(l & 0xff);
	*((c)++) = (unsigned char)(((l) >> 8L) & 0xff);
	*((c)++) = (unsigned char)(((l) >> 16L) & 0xff);
	*((c)++) = (unsigned char)(((l) >> 24L) & 0xff);
}

/**
 * Converts a character into a hexidecimal integer
 * @param character - the character to convert
 * @return - the converted character, or 'z' on error
 */
unsigned char DES_452::charToHex(const char& character)
{
	/* Is the first digit 0-9 ? */
	if (character >= '0' && character <= '9')
		/* Convert the character to hex */
		return character - '0';
	/* It the first digit a letter 'a' - 'f'? */
	else if (character >= 'a' && character <= 'f')
		/* Conver the cgaracter to hex */
		return (character - 97) + 10;
	/* Invalid character */
	else return 'z';
}

/**
 * Converts two characters into a hex integers
 * and then inserts the integers into the higher
 * and lower bits of the byte
 * @param twoChars - two charcters representing the
 * the hexidecimal nibbles of the byte.
 * @param twoChars - the two characters
 * @return - the byte containing having the
 * valud of two characters e.g. string "ab"
 * becomes hexidecimal integer 0xab.
 */
unsigned char DES_452::twoCharToHexByte(const unsigned char* twoChars)
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


