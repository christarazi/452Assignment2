# 452Assignment2

C++ program for CPSC 452 assignment 2. Extra credit (implementing DES modes) is included.

## Authors
 - Chris Tarazi
 - Austin Greene

## Instructions

```shell
$ make clean	# Cleans up all files from previous build.
$ make 			# Builds the entire project.
$ ./cipher 		# Runs the program.
```

### Arguments for DES / RSA

```shell
# For running DES:
# Note: DES supports the following modes: ECB, CBC, CFB.
$ ./cipher <CIPHERTYPE> <DESKEY> <MODE> <ENC/DEC> (<IV> empty string if ECB) <INPUTFILE> <OUTPUT FILE>

	# This is encrypting for CFB mode.
	$ ./cipher des "954e99ec069e50f9" cfb enc "954e99ec069e50f9" /tmp/sample.txt /tmp/sample.txt.enc 

	# This is decrypting for CFB mode.
	$ ./cipher des "954e99ec069e50f9" cfb dec "954e99ec069e50f9" /tmp/sample.txt.enc /tmp/sample.txt.dec
```

```shell
# For running RSA:
$ ./cipher <CIPHERTYPE> <RSAPUBKEYFILE> <RSAPRIVKEYFILE> <ENC/DEC> <INPUTFILE> <OUTPUT FILE>

	# This is encryption.
	$ ./cipher rsa pubkey.pem privkey.pem enc /tmp/sample.txt /tmp/sample.txt.enc

	# This is decryption.
	$ ./cipher rsa pubkey.pem privkey.pem dec /tmp/sample.txt.enc /tmp/sample.txt.dec
```

## Contributing

Please make sure that all changes you make are made first, in your own branch, then we can merge them in after review. 

To make a new branch:
```shell
$ git checkout -b <new_branch>
```
