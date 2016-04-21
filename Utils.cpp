#include "Utils.h"

using namespace std;

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

DESMode getDESMode(string arg)
{
	DESMode mode;
	transform(arg.begin(), arg.end(), arg.begin(), ::tolower);

	if (arg.compare("ecb") == 0)
		mode = ECB;
	else if (arg.compare("cbc") == 0)
		mode = CBC;
	else if (arg.compare("cfb") == 0)
		mode = CFB;
	else
		mode = UnknownMode;

	return mode;
}

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
