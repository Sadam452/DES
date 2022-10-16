# Data Encryption Standard
```
The Data Encryption Standard (DES) is a symmetric-key block cipher published by the National Institute of Standards and Technology (NIST).
DES is an implementation of a Feistel Cipher. It uses 16 round Feistel structure. The block size is 64-bit. 
Though, key length is 64-bit, DES has an effective key length of 56 bits, since 8 of the 64 bits of the key are not used by the encryption algorithm (function as check bits only).
```
# How to run the code?
1) cd DES
2) Run the command "gcc des.c"
3) then ./a.out
4) Program will ask for your choice. Enter 1 to encrypt ,2 for decrypt, And 3 for exit.
By choosing 1 or 2, Program will ask for key and initial vector. use same key and iv for both encryption and decryption.
in case of encryption, plaintext is taken from "plaintext.txt" file and ciphertext is written to "ciphertext.txt".
In case of decryption, input file is "ciphertext.txt" and output file is "plaintext_back.txt".
<br><hr>
**Test data: <br>
plaintext = 12341234abcdabcd
Key = 01234567891234a
iv = 133457799bbabcde
