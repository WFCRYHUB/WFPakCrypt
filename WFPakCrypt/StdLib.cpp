#include "WFPakCrypt.h"

/*
File functions
*/

bool fexists_(const char* filename){
	return (GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES);
}

bool fexists_W(const wchar_t* filename){
	return (GetFileAttributesW(filename) != INVALID_FILE_ATTRIBUTES);
}


file fopen_(const char *_filename, const char *_mode){
	register unsigned long acc = 0, disp = 0, share = 0;
	file hFile;
	BOOL is_append = FALSE;
	if (*_mode && *(_mode+1) == '+'){
		switch (*_mode){
			case 'r':
				acc = GENERIC_READ | GENERIC_WRITE; disp = OPEN_EXISTING;
				break;
			case 'w':
				acc = GENERIC_READ | GENERIC_WRITE; disp = CREATE_ALWAYS;
				break;
			case 'a':
				acc = GENERIC_READ | GENERIC_WRITE; disp = OPEN_ALWAYS;
				is_append = TRUE;
				break;
			default:
				return INVALID_FILE;
		}
	} else if (*_mode){
		switch (*_mode){
			case 'r':
				acc = GENERIC_READ; disp = OPEN_EXISTING; share = FILE_SHARE_READ;
				break;
			case 'w':
				acc = GENERIC_WRITE; disp = CREATE_ALWAYS;
				break;
			case 'a':
				acc = GENERIC_WRITE; disp = OPEN_ALWAYS;
				is_append = TRUE;
				break;
			default:
				return INVALID_FILE;
		}
	} else return INVALID_FILE;
	if ((hFile = CreateFileA(_filename, acc, share, NULL, disp, 0, NULL)) == INVALID_FILE) return INVALID_FILE;
	if (is_append) SetFilePointer(hFile, 0, NULL, SEEK_END);
	return hFile;
}



file fopen_W(const wchar_t *_filename, const wchar_t *_mode){
	register unsigned long acc = 0, disp = 0;
	file hFile;
	BOOL is_append = FALSE;
	if (*_mode && *(_mode+1) == '+'){
		switch (*_mode){
			case 'r':
				acc = GENERIC_READ | GENERIC_WRITE; disp = OPEN_EXISTING;
				break;
			case 'w':
				acc = GENERIC_READ | GENERIC_WRITE; disp = CREATE_ALWAYS;
				break;
			case 'a':
				acc = GENERIC_READ | GENERIC_WRITE; disp = OPEN_ALWAYS;
				is_append = TRUE;
				break;
			default:
				return INVALID_FILE;
		}
	} else if (*_mode){
		switch (*_mode){
			case 'r':
				acc = GENERIC_READ; disp = OPEN_EXISTING;
				break;
			case 'w':
				acc = GENERIC_WRITE; disp = CREATE_ALWAYS;
				break;
			case 'a':
				acc = GENERIC_WRITE; disp = OPEN_ALWAYS;
				is_append = TRUE;
				break;
			default:
				return INVALID_FILE;
		}
	} else return INVALID_FILE;
	if ((hFile = CreateFileW(_filename, acc, 0, NULL, disp, 0, NULL)) == INVALID_FILE) return INVALID_FILE;
	if (is_append) SetFilePointer(hFile, 0, NULL, SEEK_END);
	return hFile;
}

void fclose_(file _file){
	CloseHandle(_file);
}

void fseteof_(file _file){
	SetEndOfFile(_file);
}

size_32 fread_(void *_buf, size_32 _ecount, file _file){
	DWORD r;
	ReadFile(_file, _buf, (DWORD)_ecount, &r, NULL);
	return (int)r;
}

size_32 fwrite_(const void *_buf, size_32 _ecount, file _file){
	DWORD w;
	WriteFile(_file, _buf, (DWORD)_ecount, &w, NULL);
	return (size_32)w;
}


size_32 fseek_(file _file, LONG _offset, INT32 _origin){
	return ((SetFilePointer(_file, _offset, NULL, _origin) == INVALID_SET_FILE_POINTER) ? 1 : 0);
}

size_32 ftell_(file _file){
	register long pos;
	pos = SetFilePointer(_file, 0, NULL, SEEK_CUR);
	return (pos == INVALID_SET_FILE_POINTER) ? 0 : (size_32)pos;
}

size_32 fsize_(file _file){
	return GetFileSize(_file, NULL);
}

bool feof_(file _file){
	return (ftell_64(_file) == fsize_64(_file));
}

size_32 filecopy_(file _in, file _out, void *_cache, size_32 _cachesize, size_32 _size){
	register size_32 r, total;

	total = 0;
	while ((r = fread_(_cache, min(_cachesize, _size), _in))){
		if (r != fwrite_(_cache, r, _out)) break;
		_size -= r;
		total += r;
	}
	return total;
}

size_64 fseek_64(file _file, size_64 _offset, INT32 _origin){
	LARGE_INTEGER res;
	res.QuadPart = _offset;
	return (SetFilePointerEx(_file, res, &res, _origin) == TRUE) ? (size_64)res.QuadPart : (size_64)-1;
}

size_64 fsize_64(file _file){
	LARGE_INTEGER res;
	return (GetFileSizeEx(_file, &res) == TRUE) ? (size_64)res.QuadPart : (size_64)(-1);
}

size_64 ftell_64(file _file){
	LARGE_INTEGER res;
	res.QuadPart = 0;
	return (SetFilePointerEx(_file, res, &res, FILE_CURRENT) == TRUE) ? (size_64)res.QuadPart : (size_64)-1;
}