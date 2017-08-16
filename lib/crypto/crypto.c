#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include "mylib.h"

uchar *MD5_encode(uchar *in, int inlen, uchar *out, int olen)
{
        MD5_CTX ctx;
	P_VALID_RET(in, NULL);
	P_VALID_RET(out, NULL);
        MD5_Init(&ctx);
        MD5_Update(&ctx, in, inlen);
        MD5_Final(out, &ctx);
	return out;
}

char *MD5_encode_str(char *in, int inlen, char *out, int olen, int upper_case)
{
	uchar out_bin[16] = {0};
	int i = 0;

	P_VALID_RET(in, NULL);
	P_VALID_RET(out, NULL);
	if (olen < sizeof(out_bin)*2+1) {
		DEBUG("obuf too low, len:%d, at least:%ld\n", olen, sizeof(out_bin)*2+1);
		return NULL;
	}
	MD5_encode((uchar *)in, inlen, out_bin, sizeof(out_bin));
	for (i = 0; i < sizeof(out_bin); i++) {
		sprintf(out + 2*i, upper_case ? "%02X" : "%02x", (uchar)out_bin[i]);
	}
	DEBUG("in:%s inlen:%d out:%s olen:%d\n", in, inlen, out, olen);
	return out;
}

int aes_cbc_128_encrypt(const char *in, unsigned char *ou, const unsigned char *secret_key, unsigned char *p_iv)
{
	int i_padding = 0, in_len = 0;
	unsigned char iv[16] = {0};
	AES_KEY  aes_key;
	char * pad_data = NULL;
	char tmp_key[64] = {0};

	if (!in || !ou || !secret_key || !p_iv)
		return -1;

	memset(&aes_key, 0, sizeof(aes_key));

	//Pkcs5Padding
	in_len		= strlen(in);
	i_padding	= AES_BLOCK_SIZE-in_len%AES_BLOCK_SIZE;
	pad_data	= (char *)malloc(in_len + i_padding + 1);
	if (!pad_data)
		return -2;
	memset(pad_data, 0, in_len+i_padding+1);
	strcpy(pad_data, in);
	memset(pad_data+in_len, i_padding, i_padding);//Padding

	memcpy(tmp_key, secret_key, 16);
	memset(&aes_key, 0, sizeof(aes_key));
	memset(iv, 0, sizeof(iv));
	memcpy(iv, p_iv, sizeof(iv));
	AES_set_encrypt_key(tmp_key, 128, &aes_key);
	AES_cbc_encrypt(pad_data, ou, in_len+i_padding, &aes_key, iv, AES_ENCRYPT);

	SAFE_FREE(pad_data);
	return (in_len+i_padding);
}

/**
 * 生成RSA结构用于加解密
 * key: 公钥/私钥buffer
 * pubic: 0 - 私钥, 1 - 公钥
 */

static RSA* create_rsa(unsigned char *key, int public) {
	RSA *rsa = NULL;
	BIO *keybio = BIO_new_mem_buf(key, -1);
	if (!keybio) {
		goto finally;
	}
	if (public) {
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	} else {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}

finally:
	BIO_free_all(keybio);
	return rsa;
}

static int rsa_encrypt(unsigned char *plain_data, int data_len, int public,
		unsigned char *key, unsigned char *encrypted_data, int padding) 
{

	int result = 0, rsaSize = 0, offset = 0, capacity = data_len, 
	    flenMax = 0, flen = 0, encrypted_len = 0;
	RSA *rsa = NULL;
	unsigned char *buf = NULL;

	P_VALID_RET(plain_data, -1);
	P_VALID_RET(key, -1);
	P_VALID_RET(encrypted_data, -1);

	rsa	= create_rsa(key, public);
	if (!rsa) {
		DEBUG("create rsa faild\n");
		return -1;
	}
	rsaSize	= RSA_size(rsa);

	switch (padding) {
		case RSA_SSLV23_PADDING:
		case RSA_PKCS1_PADDING:
			flenMax	= rsaSize - 11;
			flen	= data_len > flenMax ? flenMax : data_len;
			break;
		case RSA_PKCS1_OAEP_PADDING:
			flenMax	= rsaSize - 41;
			flen	= data_len > flenMax ? flenMax : data_len;
			break;
		case RSA_NO_PADDING:
			flenMax	= rsaSize;
			flen	= flenMax;
			capacity = (data_len/rsaSize + (data_len%rsaSize?1:0)) * rsaSize;
			buf 	= (unsigned char *)malloc(capacity + 1);
			if (!buf) {
				return -1;
			}
			memset(buf, 0, capacity + 1);
			memcpy(buf, plain_data, data_len);
			break;
		default:
			DEBUG("unknown padding mode:%d\n", padding);
			return -1;
	}

	//DEBUG("rsaSize:%d capacity:%d data_len:%d flen:%d\n", rsaSize, capacity, data_len, flen);
	while (offset < capacity)
	{
		if (public)
			result	= RSA_public_encrypt(flen, (buf?buf:plain_data)+offset, 
				encrypted_data+encrypted_len, rsa, padding);
		else
			result	= RSA_private_encrypt(flen, (buf?buf:plain_data)+offset, 
				encrypted_data+encrypted_len, rsa, padding);

		if (result == -1) {
			DEBUG("RSA_%s_encrypt failed!\n", public?"public":"private");
			break;
		}
		offset		+= flen;
		encrypted_len	+= result;
		flen	= ((capacity - offset) > flen) ? flen : (capacity - offset);
	}

	/* 释放内存 */
	if (buf) {
		free(buf);
	}

	/* 释放RSA结构 */
	if (rsa) {
		RSA_free(rsa);
	}

	return result==-1 ? -1 : encrypted_len;
}

static int rsa_decrypt(unsigned char *encrypted_data, int data_len, int public,
		unsigned char *key, unsigned char *plain_data, int padding) 
{
	int result = 0, rsaSize = 0, offset = 0, capacity = data_len, decrypted_len = 0;
	RSA *rsa = NULL;

	P_VALID_RET(plain_data, -1);
	P_VALID_RET(key, -1);
	P_VALID_RET(encrypted_data, -1);

	rsa	= create_rsa(key, public);
	if (!rsa) {
		DEBUG("create rsa faild\n");
		return -1;
	}
	rsaSize	= RSA_size(rsa);

	DEBUG("rsaSize:%d capacity:%d data_len:%d\n", rsaSize, capacity, data_len);
	while (offset < capacity)
	{
		if (public)
			result	= RSA_public_decrypt(rsaSize, encrypted_data+offset, 
				plain_data+decrypted_len, rsa, padding);
		else
			result	= RSA_private_decrypt(rsaSize, encrypted_data+offset, 
				plain_data+decrypted_len, rsa, padding);
		if (result == -1) {
			DEBUG("RSA_%s_decrypt failed!\n", public?"public":"private");
			break;
		}
		offset		+= rsaSize;
		decrypted_len	+= result;
		DEBUG("offset:%d decrypted_len:%d\n", offset, decrypted_len);
	}

	/* 释放RSA结构 */
	if (rsa) {
		RSA_free(rsa);
	}

	return result==-1 ? -1 : decrypted_len;
}

/**
 * 公钥加密
 * plain_data: 明文数据
 * data_len: 待加密串长度
 * key: 公钥字符
 * encrypted_data: 加密后的数据
 */
int rsa_public_encrypt(unsigned char *plain_data, int data_len, 
		unsigned char *key, unsigned char *encrypted_data, int padding) 
{
	return rsa_encrypt(plain_data, data_len, 1, key, encrypted_data, padding);
}

/**
 * 公钥解密
 */
int rsa_public_decrypt(unsigned char *encrypted_data, int data_len, 
		unsigned char *key, unsigned char *plain_data, int padding) 
{
	return rsa_decrypt(encrypted_data, data_len, 1, key, plain_data, padding);
}

/**
 * 私钥加密
 */
int rsa_private_encrypt(unsigned char *plain_data, int data_len, 
		unsigned char *key, unsigned char *encrypted_data, int padding) 
{
	return rsa_encrypt(plain_data, data_len, 0, key, encrypted_data, padding);	
}

/**
 * 私钥解密
 */
int rsa_private_decrypt(unsigned char *encrypted_data, int data_len, 
		unsigned char *key, unsigned char *plain_data, int padding) 
{
	return rsa_decrypt(encrypted_data, data_len, 0, key, plain_data, padding);
}

static uchar public_key_test[] = "-----BEGIN PUBLIC KEY-----\n"
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+Ifzq5BTTK6cSBGLX2Ue49HWy\n"
"Me4165jQdpi7awA4J4QVYZFUBLxzKyaGpqAvqosdjxaU6L2RZNGEJkiMaJok/q0n\n"
"inH4lJCElklFcpyx26mY7R2gbjv9boF7oKNm9WUGIchM/gSRoBxQjGH5Hh8jW9c0\n"
"HOngGg/yfD5XOoSk5QIDAQAB\n"
"-----END PUBLIC KEY-----\n";
static uchar private_key_test[] = "-----BEGIN PRIVATE KEY-----\n"
"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAL4h/OrkFNMrpxIE\n"
"YtfZR7j0dbIx7jXrmNB2mLtrADgnhBVhkVQEvHMrJoamoC+qix2PFpTovZFk0YQm\n"
"SIxomiT+rSeKcfiUkISWSUVynLHbqZjtHaBuO/1ugXugo2b1ZQYhyEz+BJGgHFCM\n"
"YfkeHyNb1zQc6eAaD/J8Plc6hKTlAgMBAAECgYBL8MdUCkVHEuhoCdhw3hgHh5x6\n"
"z/aVEsS2fqgCM3qi8yWOZKnnJP0gAtwga+0PHM7zv3MFhvAwYlRMs/3GFwF5lP3n\n"
"9B+PzgXpIWtLTtrs1k4I6CYZeGSFLw+vxZjtLh7Qz16bVa8Cu20s22WLxdu0/QwK\n"
"jQssOSfiijSmdtbzAQJBAN+VOVrV9Nvamcx6wNzFeMvO2i5iOwv7A0sTFjiCOsIB\n"
"YqxHWcpOyXriB3gQ98IKuyZHSq46DigY+0jmapwX1FMCQQDZszALO5W9gW04ZO0r\n"
"r9UPR1lxSNZgZU3R26FJX+TG/P+knBKcw1AuJdy2P7j0atWAqYAIcywI7U5Wyz4w\n"
"SfrnAkBMJHa+76SPBxhfoeJyjTHBPvXg3AU95ENP2vUzU26NSYmAIGB83G4TUky2\n"
"4BhwVdU8iQTu5siRcUiKoCXoeNkPAkBcalnx2siVWxUvhIC+M/WBd+t7UM1YvIiN\n"
"luvgBypKYupvSaYJEEzAWmhYobJ1Z8jcxpfIfoPqAjtoUv1CaJVvAkBzLgkjSHEK\n"
"agZcmZp0oJonb7i512F0CnlGShXbTstX3iPfJ3Uyf3VhglGBUvnjY+RMXmedIxp2\n"
"7ftr4YO+QYwD\n"
"-----END PRIVATE KEY-----\n";

static int rsa_encrypt_test()
{
	//uchar *buf = "1234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678";
	uchar *buf = "12345678";
	uchar rsa_res[1024] = {0};
	uchar obuf[1024] = {0};
	int olen = sizeof(obuf), rsa_len = 0;

	rsa_len	= rsa_private_encrypt(buf, strlen(buf), private_key_test, rsa_res, RSA_PKCS1_PADDING);
	DEBUG("buf len:%d rsa_len:%d\n", (int)strlen(buf), rsa_len);
	igd_base64_encode(rsa_res, rsa_len, obuf, &olen);
	DEBUG("%s len:%d\n", obuf, olen);
	rsa_len = rsa_public_decrypt(rsa_res, rsa_len, public_key_test, obuf, RSA_PKCS1_PADDING);
	DEBUG("%s len:%d\n", obuf, rsa_len);
	return 0;
}
