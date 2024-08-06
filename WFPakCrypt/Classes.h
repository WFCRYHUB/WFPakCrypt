#pragma once

#define HeaderEncryption_None 0
#define HeaderEncryption_StreamCipher 1
#define HeaderEncryption_XXTEA 2
#define HeaderEncryption_Twofish 3

enum ECustomEncryptionType {
	ENCRYPTION_NO = 0,
	ENCRYPTION_OLD = 1,
	ENCRYPTION_RSA = 2
};

struct CustomEncryptionHeader {
	UINT32	nHeaderSize;
	UINT8	CDR_hash[32];
	UINT8	CDR_signed[128];
	UINT8	CDR_IV[16];
	UINT8	CDR_encrypted_key[128];
	UINT8	keys_table[16][128];
};

struct CustomExtendedHeader {
	UINT32					nHeaderSize;
	ECustomEncryptionType	nEncryption;
};

namespace ZipFile
{
#pragma pack(push, 1)
	struct CDREnd {
		DWORD	lSignature;
		USHORT	nDisk;
		USHORT	nCDRStartDisk;
		USHORT	numEntriesOnDisk;
		USHORT	numEntriesTotal;
		DWORD	lCDRSize;
		DWORD	lCDROffset;
		USHORT	nCommentLength;
	};
	struct DataDescriptor {
		UINT32	lCRC32;
		UINT32	lSizeCompressed;
		UINT32	lSizeUncompressed;
	};
	struct LocalFileHeader {
		UINT32			lSignature;
		UINT16			nVersionNeeded;
		UINT16			nFlags;
		UINT16			nMethod;
		UINT16			nLastModTime;
		UINT16			nLastModDate;
		DataDescriptor	desc;
		UINT16			nFileNameLength;
		UINT16			nExtraFieldLength;
	};
	struct CDRFileHeader {
		long			lSignature;
		USHORT			nVersionMadeBy;
		USHORT			nVersionNeeded;
		USHORT			nFlags;
		USHORT			nMethod;
		USHORT			nLastModTime;
		USHORT			nLastModDate;
		DataDescriptor	desc;
		USHORT			nFileNameLength;
		USHORT			nExtraFieldLength;
		USHORT			nFileCommentLength;
		USHORT			nDiskNumberStart;
		USHORT			nAttrInternal;
		long			lAttrExternal;
		long			lLocalHeaderOffset;
	};
#pragma pack(pop)
};

