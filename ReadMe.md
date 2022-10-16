Run the command "gcc des.c"
then ./a.out
Program will ask for your choice. Enter 1 to encrypt ,2 for decrypt, And 3 for exit.
By choosing 1 or 2, Program will ask for key and initial vector. use same key and iv for both encryption and decryption.
in case of encryption, plaintext is taken from "plaintext.txt" file and ciphertext is written to "ciphertext.txt".
In case of decryption, input file is "ciphertext.txt" and output file is "plaintext_back.txt".
I have tested it on following data:
plaintext = 4e6f772069732074
Key = 0123456789abcdef
iv = 133457799bbcdff0
