#include "WFPakCrypt.h"

rsa_key		g_rsa_key_public_for_sign;
prng_state	g_yarrow_prng_state;

namespace ZipEncrypt {

	int custom_rsa_decrypt_key_ex(
		const unsigned char* in, unsigned long	inlen,
		unsigned char* out, unsigned long* outlen,
		const unsigned char* lparam, unsigned long	lparamlen,
		int						hash_idx, int				padding,
		int* stat, rsa_key* key)
	{
		unsigned long modulus_bitlen, modulus_bytelen, x;
		int           err;
		unsigned char* tmp;

		LTC_ARGCHK(out != NULL);
		LTC_ARGCHK(outlen != NULL);
		LTC_ARGCHK(key != NULL);
		LTC_ARGCHK(stat != NULL);

		/* default to invalid */
		*stat = 0;

		/* valid padding? */

		if ((padding != LTC_LTC_PKCS_1_V1_5) &&
			(padding != LTC_LTC_PKCS_1_OAEP)) {
			return CRYPT_PK_INVALID_PADDING;
		}

		if (padding == LTC_LTC_PKCS_1_OAEP) {
			/* valid hash ? */
			if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
				return err;
			}
		}

		/* get modulus len in bits */
		modulus_bitlen = mp_count_bits((key->N));

		/* outlen must be at least the size of the modulus */
		modulus_bytelen = mp_unsigned_bin_size((key->N));
		if (modulus_bytelen != inlen) {
			return CRYPT_INVALID_PACKET;
		}

		/* allocate ram */
		tmp = (unsigned char*)XMALLOC(inlen);
		if (tmp == NULL) {
			return CRYPT_MEM;
		}

		/* rsa decode the packet */
		x = inlen;
		if ((err = ltc_mp.rsa_me(in, inlen, tmp, &x, PK_PUBLIC, key)) != CRYPT_OK) {
			XFREE(tmp);
			return err;
		}

		if (padding == LTC_LTC_PKCS_1_OAEP) {
			/* now OAEP decode the packet */
			err = pkcs_1_oaep_decode(tmp, x, lparam, lparamlen, modulus_bitlen, hash_idx,
				out, outlen, stat);
		}
		else {
			/* now LTC_PKCS #1 v1.5 depad the packet */
			err = pkcs_1_v1_5_decode(tmp, x, LTC_LTC_PKCS_1_EME, modulus_bitlen, out, outlen, stat);
		}

		XFREE(tmp);
		return err;
	}

	bool DecryptBufferWithStreamCipher(char* inBuffer, unsigned int bufferSize, char* key, char* IV)
	{
		symmetric_CTR ctr;
		int cipher = find_cipher("twofish");
		if (cipher < 0)
			return false;

		if (ctr_start(cipher, (unsigned char*)IV, (unsigned char*)key, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr) != CRYPT_OK)
			return false;
		if (ctr_decrypt((unsigned char*)inBuffer, (unsigned char*)inBuffer, bufferSize, &ctr) != CRYPT_OK)
			return false;
		ctr_done(&ctr);
		return true;
	}

	bool RSA_VerifyData(void* inBuffer, int sizeIn, char* signedHash, int signedHashSize, rsa_key* publicKey)
	{
		/*int v5;
		char hash_digest[1024];
		Hash_state md;
		int statOut;

		int sha256 = find_hash("sha256");
		((void(__cdecl*)(Hash_state*))dword_1C52F84[26 * v5])(&md);
		((void(__cdecl*)(Hash_state*, void*, int))dword_1C52F88[26 * v5])(&md, inBuffer, sizeIn);
		((void(__cdecl*)(Hash_state*, char*))dword_1C52F8C[26 * v5])(&md, hash_digest);
		find_prng("yarrow");
		statOut = 0;
		return !rsa_verify_hash_ex(
			(int)signedHash,
			signedHashSize,
			(int)hash_digest,
			32,
			3,
			sha256,
			0,
			(int)&statOut,
			(int)publicKey)
			&& statOut == 1;*/
		return true;
	}
}