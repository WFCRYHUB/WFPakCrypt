#pragma once

#define g_nCDRSearchWindowSize		0x100
#define SIGNATURE_CDREnd			0x6054B50
#define SIGNATURE_LocalFileHeader	0x4034b50

using namespace ZipFile;

// ZipDir & ZipDir::CacheFactory from CE
class ZipDir {

public:
	bool Prepare(file f);
	bool FindCDREnd(file f);
	bool DecryptKeysTable();
	bool ReadHeaderData(char* pDest, unsigned int nSize, bool older_support);
	int SwitchMethod(int method);
	bool BuildFileEntryMap(file f, file fo, bool older_support);
	bool Decrypt(char* pData, int len, DataDescriptor &desc);

protected:
	// Warface custom encryption headers
	CustomExtendedHeader m_headerExtended;
	CustomEncryptionHeader m_headerEncryption;
	UINT8 m_block_cipher_cdr_key[16];
	UINT8 m_block_cipher_keys_table[16][16];


	CDREnd m_CDREnd;
	unsigned m_nCDREndPos;
	unsigned char m_encryptedHeaders;

};