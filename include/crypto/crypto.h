#ifndef __CRYPTO_H__
#define __CRYPTO_H__

uchar *MD5_encode(uchar *in, int inlen, uchar *out, int olen);
char *MD5_encode_str(char *in, int inlen, char *out, int olen, int upper_case);

int rsa_public_encrypt(unsigned char *plain_data, int data_len, 
		unsigned char *key, unsigned char *encrypted_data, int padding);
int rsa_public_decrypt(unsigned char *encrypted_data, int data_len, 
		unsigned char *key, unsigned char *plain_data, int padding);
int rsa_private_encrypt(unsigned char *plain_data, int data_len, 
		unsigned char *key, unsigned char *encrypted_data, int padding);
int rsa_private_decrypt(unsigned char *encrypted_data, int data_len, 
		unsigned char *key, unsigned char *plain_data, int padding);
#endif
