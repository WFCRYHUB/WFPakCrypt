#include "WFPakCrypt.h"

extern "C" __declspec(dllexport) void InitRSA(unsigned char* rsa_key, int rsa_size)
{
	ltc_mp = ltm_desc;
	register_hash(&sha1_desc);
	register_hash(&sha256_desc);
	register_cipher(&twofish_desc);
	register_prng(&yarrow_desc);
	rng_make_prng(128, find_prng("yarrow"), &g_yarrow_prng_state, NULL);
	rsa_import(rsa_key, rsa_size, &g_rsa_key_public_for_sign);
}

extern "C" __declspec(dllexport) bool DecryptPak(const char* fin, const char* fout, bool older_support) {
	file f = fopen_(fin, "r");
	file fo = fopen_(fout, "w");

	if (f == NULL || fo == NULL)
		return false;

	ZipDir zipDir;
	if (!zipDir.FindCDREnd(f))
		return false;
	if (!zipDir.Prepare(f))
		return false;
	if (!zipDir.BuildFileEntryMap(f, fo, older_support))
		return false;

	if (fo)
		fclose_(fo);
	if (f)
		fclose_(f);

	return true;
}