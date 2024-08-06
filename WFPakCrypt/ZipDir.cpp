#include "WFPakCrypt.h"

using namespace ZipFile;

bool ZipDir::Prepare(file f)
{
	m_encryptedHeaders = (m_CDREnd.nDisk & 0xC000) >> 14;
	m_CDREnd.nDisk = m_CDREnd.nDisk & 0x3fff;

	if (m_CDREnd.nDisk != 0
		|| m_CDREnd.nCDRStartDisk != 0
		|| m_CDREnd.numEntriesOnDisk != m_CDREnd.numEntriesTotal)
	{
		printf("CE: Multivolume archive detected. Current version of ZipDir does not support multivolume archives");
		return false;
	}

	if (m_CDREnd.lCDROffset > m_nCDREndPos
		|| m_CDREnd.lCDRSize > m_nCDREndPos
		|| m_CDREnd.lCDROffset + m_CDREnd.lCDRSize > m_nCDREndPos)
	{
		printf("CE: The central directory offset or size are out of range, the pak is probably corrupt, try to repare or delete the file");
		return false;
	}

	if (m_CDREnd.nCommentLength >= 8u)
	{
		fseek_(f, m_CDREnd.lCDROffset + m_CDREnd.lCDRSize + sizeof(CDREnd), SEEK_SET);

		if (!fread_b(&m_headerExtended, sizeof(CustomExtendedHeader), f))
		{
			printf("fread_b -> m_headerExtended");
			return false;
		}

		if (m_CDREnd.nCommentLength >= sizeof(CustomEncryptionHeader))
		{
			if (!fread_b(&m_headerEncryption, sizeof(CustomEncryptionHeader), f))
			{
				printf("fread_b -> m_headerEncryption");
				return false;
			}

			if (m_headerEncryption.nHeaderSize != sizeof(CustomEncryptionHeader))
			{
				printf("m_headerEncryption.nHeaderSize != sizeof(CustomEncryptionHeader)");
				return false;
			}

			if (!DecryptKeysTable())
			{
				printf("Failed to DecryptKeysTable");
				return false;
			}
		}
	}
}


bool ZipDir::FindCDREnd(file f)
{
	fseek_(f, 0, SEEK_END);
	unsigned long nFileSize = ftell_(f);

	if (nFileSize < sizeof(CDREnd))
	{
		printf("CE: The file is too small, it doesn't even contain the CDREnd structure. Please check and delete the file. Truncated files are not deleted automatically");
		return false;
	}

	unsigned int nOldBufPos = nFileSize;
	unsigned int nScanPos = nFileSize - sizeof(CDREnd);

	m_CDREnd.lSignature = 0;
	while (true)
	{
		char* pReservedBuffer = new char[g_nCDRSearchWindowSize + sizeof(CDREnd) - 1];

		unsigned int nNewBufPos;
		char* pWindow = pReservedBuffer;
		if (nOldBufPos <= g_nCDRSearchWindowSize)
		{
			nNewBufPos = 0;
			pWindow = pReservedBuffer + g_nCDRSearchWindowSize - (nOldBufPos - nNewBufPos);
		}
		else
		{
			nNewBufPos = nOldBufPos - g_nCDRSearchWindowSize;
			assert(nNewBufPos > 0);
		}

		if (nFileSize > (sizeof(CDREnd) + 0xFFFF))
		{
			if (nNewBufPos < (unsigned int)(nFileSize - sizeof(CDREnd) - 0xFFFF))
			{
				nNewBufPos = nFileSize - sizeof(CDREnd) - 0xFFFF;
			}
		}

		if (nNewBufPos >= nOldBufPos)
		{
			printf("CE: Cant find central directory (CDR)");
			return false;
		}

		fseek_(f, nNewBufPos, SEEK_SET);
		fread_(pWindow, nOldBufPos - nNewBufPos, f);

		while (nScanPos >= nNewBufPos)
		{
			CDREnd* pEnd = (CDREnd*)(pWindow + nScanPos - nNewBufPos);
			if (pEnd->lSignature == SIGNATURE_CDREnd)
			{
				if (pEnd->nCommentLength == nFileSize - nScanPos - sizeof(CDREnd))
				{
					m_CDREnd = *pEnd;
					m_nCDREndPos = nScanPos;
					break;
				}
				else
				{
					printf("CE: Central Directory Record is followed by a comment of inconsistent length. This might be a minor misconsistency, please try to repair the file. However, it is dangerous to open the file because I will have to guess some structure offsets, which can lead to permanent unrecoverable damage of the archive content");
					return false;
				}
			}
			if (nScanPos == 0)
				break;
			--nScanPos;
		}

		if (m_CDREnd.lSignature == SIGNATURE_CDREnd) {
			return true;
		}

		nOldBufPos = nNewBufPos;
		memmove(pReservedBuffer + g_nCDRSearchWindowSize, pWindow, sizeof(CDREnd) - 1);
	}
	printf("CE: The program flow may not have possibly lead here. This error is unexplainable");
}


bool ZipDir::DecryptKeysTable() {
	int hash, stat;
	int i;
	unsigned long outlen;
	unsigned char buf[1024];
	hash = find_hash("sha1");
	outlen = sizeof(buf);
	if (ZipEncrypt::custom_rsa_decrypt_key_ex(m_headerEncryption.CDR_encrypted_key, 128, buf, &outlen, NULL, 0, hash, LTC_LTC_PKCS_1_OAEP, &stat, &g_rsa_key_public_for_sign) != CRYPT_OK || stat != 1 || outlen != 16)
	{
		printf("custom_rsa_decrypt_key_ex m_headerEncryption.CDR_encrypted_key");
		return false;
	}
	memcpy(m_block_cipher_cdr_key, buf, 16);
	for (i = 0; i < 16; i++) {
		outlen = sizeof(buf);
		if (ZipEncrypt::custom_rsa_decrypt_key_ex(m_headerEncryption.keys_table[i], 128, buf, &outlen, NULL, 0, hash, LTC_LTC_PKCS_1_OAEP, &stat, &g_rsa_key_public_for_sign) != CRYPT_OK || stat != 1 || outlen != 16)
		{
			printf("custom_rsa_decrypt_key_ex m_headerEncryption.keys_table[%i]", i);
			return false;
		}
		memcpy(m_block_cipher_keys_table[i], buf, 16);
	}
	return true;
}


bool ZipDir::ReadHeaderData(char* pDest, unsigned int nSize, bool older_support)
{
	char* pKey;
	if (older_support)
		pKey = (char*)m_block_cipher_cdr_key;
	else 
		pKey = (char*)m_block_cipher_keys_table;

	if (m_headerExtended.nEncryption == ECustomEncryptionType::ENCRYPTION_RSA)
	{
		if (!ZipEncrypt::DecryptBufferWithStreamCipher(
			pDest,
			nSize,
			pKey,
			(char*)m_headerEncryption.CDR_IV)
			|| !ZipEncrypt::RSA_VerifyData(pDest, nSize, (char*)m_headerEncryption.CDR_signed, 128, &g_rsa_key_public_for_sign))
		{
			return false;
		}
	}
	else
	{
		/* Never use */
		//ZipDir::Decrypt((char*)pDest, nSize);
	}
	return true;
}


int  ZipDir::SwitchMethod(int method) {
	switch (method) { 
	default: return method;
	case 11: return 8;
	case 13: return 0;
	case 14: return 8;
	case 12: return 0;
	} 
}


bool ZipDir::BuildFileEntryMap(file f, file fo, bool older_support)
{
	char* pDest, *pEndOfData, *pFileName, *pEndOfRecord, *pSrc;
	CDRFileHeader* pFile;


	m_CDREnd.nCommentLength = 0;

	fseek_(fo, m_nCDREndPos, SEEK_SET);
	if (!fwrite_b(&m_CDREnd, sizeof(CDREnd), fo))
	{
		printf("fwrite_b -> m_CDREnd");
		return false;
	}


	pDest = new char[m_CDREnd.lCDRSize];

	fseek_(f, m_CDREnd.lCDROffset, SEEK_SET);
	if (!fread_b(pDest, m_CDREnd.lCDRSize, f))
	{
		printf("fread_b -> pDest");
		return false;
	}

	// Decrypt custom

	if (!ReadHeaderData(pDest, m_CDREnd.lCDRSize, older_support))
	{
		printf("Failed to decrypt custom ReadHeaderData");
		return false;
	}


	fseek_(fo, m_CDREnd.lCDROffset, SEEK_SET);
	if (!fwrite_b(pDest, m_CDREnd.lCDRSize, fo))
	{
		printf("fwrite_b -> pDest");
		return false;
	}


	pFile		= (CDRFileHeader*)(pDest);
	pEndOfData	= pDest + m_CDREnd.lCDRSize;
	pFileName	= pDest + sizeof(CDRFileHeader);


	for (;pFileName <= pEndOfData; pFile = (CDRFileHeader*)pEndOfRecord, pFileName = pEndOfRecord + sizeof(CDRFileHeader))
	{
		pFile->lSignature = 0;

		if (pFile->nVersionNeeded > 20) {
			printf("Cannot read the archive file (nVersionNeeded > 20).\n");
			return false;
		}

		pEndOfRecord = pFileName + pFile->nExtraFieldLength + pFile->nFileNameLength + pFile->nFileCommentLength;

		if (pEndOfRecord > pEndOfData)
		{
			printf("Central Directory record is either corrupt, or truncated, or missing. Cannot read the archive directory.\n");
			return false;
		}

		unsigned nBufferLength = sizeof(LocalFileHeader) + pFile->nFileNameLength + pFile->nExtraFieldLength;
		char* buf = new char[nBufferLength];

		fseek_(f, pFile->lLocalHeaderOffset, SEEK_SET);
		if (!fread_b(buf, nBufferLength + pFile->nExtraFieldLength + pFile->nFileCommentLength, f))
		{
			printf("fread_b -> pLocalFileHeader");
			return false;
		}

		LocalFileHeader* pLocalFileHeader	= (LocalFileHeader*)buf;
		pLocalFileHeader->desc				= pFile->desc;
		pLocalFileHeader->nFileNameLength	= pFile->nFileNameLength;
		pLocalFileHeader->nFlags			= 0;
		pLocalFileHeader->lSignature		= SIGNATURE_LocalFileHeader;
		pLocalFileHeader->nExtraFieldLength = 0;
		pLocalFileHeader->nVersionNeeded	= 20;
		pLocalFileHeader->nLastModDate		= pFile->nLastModDate;
		pLocalFileHeader->nLastModTime		= pFile->nLastModTime;
		pLocalFileHeader->nMethod			= SwitchMethod(pFile->nMethod);
		memcpy(pLocalFileHeader + 1, pFileName, pFile->nFileNameLength);

		fseek_(fo, pFile->lLocalHeaderOffset, SEEK_SET);
		if (!fwrite_(pLocalFileHeader, nBufferLength + pFile->nExtraFieldLength + pFile->nFileCommentLength, fo))
		{
			printf("fwrite_b -> pLocalFileHeader");
			return false;
		}


		pSrc = new char[pFile->desc.lSizeCompressed];

		fseek_(f, nBufferLength + pFile->lLocalHeaderOffset, 0);
		if (!fread_b(pSrc, pFile->desc.lSizeCompressed, f))
		{
			printf("fread_b -> pSrc");
			return false;
		}


		if (!Decrypt(pSrc, pFile->desc.lSizeCompressed, pFile->desc)) {
			printf("Cannot decrypt file.");
			return false;
		}


		pFile->nMethod = 0;

		fseek_(fo, nBufferLength + pFile->lLocalHeaderOffset, SEEK_SET);
		if (!fwrite_b(pSrc, pFile->desc.lSizeCompressed, fo))
		{
			printf("fwrite_b -> pSrc");
			return false;
		}

		delete[] pSrc;
		pSrc = nullptr;
	}

	fseek_(fo, m_CDREnd.lCDROffset, SEEK_SET);
	if (!fwrite_b(pDest, m_CDREnd.lCDRSize, fo))
	{
		printf("fwrite_b -> pDest");
		return false;
	}

	delete[] pDest, pEndOfData, pFileName, pEndOfRecord;
	pDest = pEndOfData = pFileName = pEndOfRecord = nullptr;
	return true;
}


bool ZipDir::Decrypt(char* pData, int len, DataDescriptor& desc) {
	unsigned char iv[16];
	int key = (~(desc.lCRC32 >> 2)) & 0xF;
	((DWORD*)iv)[0] = (desc.lSizeCompressed << 12) ^ desc.lSizeUncompressed;
	((DWORD*)iv)[1] = !desc.lSizeCompressed;
	((DWORD*)iv)[2] = (desc.lSizeCompressed << 12) ^ desc.lCRC32;
	((DWORD*)iv)[3] = desc.lSizeCompressed ^ (!desc.lSizeUncompressed);
	return ZipEncrypt::DecryptBufferWithStreamCipher(pData, len, (char*)m_block_cipher_keys_table[key], (char*)iv);
}