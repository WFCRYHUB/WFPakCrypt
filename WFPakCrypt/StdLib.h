#ifndef _STDLIB_H_
#define _STDLIB_H_

/*
File stuff
*/

typedef UINT64	size_64;
typedef UINT32	size_32;

#define file				HANDLE
#define INVALID_FILE		(INVALID_HANDLE_VALUE)
#define VALID_FILE(file)	((file) != INVALID_FILE)

bool fexists_(const char* filename);
bool fexists_W(const wchar_t* filename);
file fopen_(const char *_filename, const char *_mode);
file fopen_W(const wchar_t *_filename, const wchar_t *_mode);
void fclose_(file _file);
void fseteof_(file _file);

size_32 fread_(void *_buf, size_32 _ecount, file _file);
size_32 fwrite_(const void *_buf, size_32 _count, file _file);

size_32 fseek_(file _file, LONG _offset, INT32 _origin);
size_32 ftell_(file _file);
size_32 fsize_(file _file);

bool feof_(file _file);

size_32 filecopy_(file _in, file _out, void *_cache, size_32 _cachesize, size_32 size);

template<typename T> bool fread_t(file f, T(&obj)){
	return (fread_(&obj, sizeof(T), f) == sizeof(T));
}
template<typename T> inline bool fwrite_t(file f, T &obj){
	return fwrite_(&obj, sizeof(T), f) == sizeof(T);
}

inline bool fwrite_b(const void* _buf, size_32 _size, file _file){
	return fwrite_(_buf, _size, _file) == _size;
}

inline bool fread_b(void* _buf, size_32 _size, file _file){
	return fread_(_buf, _size, _file) == _size;
}

inline void falign_(file f, size_32 align){
	size_32 offset;
	offset = (ftell_(f)+(align-1))/align*align;
	fseek_(f, offset, SEEK_SET);
}

/*
64 bit file support
*/

size_64 fseek_64(file _file, size_64 _offset, INT32 _origin);
size_64 fsize_64(file _file);
size_64 ftell_64(file _f);

#endif //_STDLIB_H_
