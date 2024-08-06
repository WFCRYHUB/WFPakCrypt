#pragma once

extern rsa_key		g_rsa_key_public_for_sign;
extern prng_state	g_yarrow_prng_state;

namespace ZipEncrypt {

	int custom_rsa_decrypt_key_ex(
		const unsigned char*	in,			unsigned long	inlen,
		unsigned char*			out,		unsigned long*	outlen,
		const unsigned char*	lparam,		unsigned long	lparamlen,
		int						hash_idx,	int				padding,
		int*					stat,		rsa_key*		key);
	bool DecryptBufferWithStreamCipher(char* inBuffer, unsigned int bufferSize, char* key, char* IV);
	bool RSA_VerifyData(void* inBuffer, int sizeIn, char* signedHash, int signedHashSize, rsa_key* publicKey);
}