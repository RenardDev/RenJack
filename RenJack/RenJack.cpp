
// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <sddl.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

// STL
#include <tuple>
#include <vector>
#include <memory>

// Custom
#include "ConsoleUtils.h"
#include "keystone.h"

#define PRINT_ERROR(x, ...) clrprintf(ConsoleColor::Red, "[!] Error: "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_WARNING(x, ...) clrprintf(ConsoleColor::DarkYellow, "[!] Warning: "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_VERBOSE(x, ...) clrprintf(ConsoleColor::Magenta, "[*] Verbose: "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_INFO(x, ...) clrprintf(ConsoleColor::Cyan, "[i] "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_POSITIVE(x, ...) clrprintf(ConsoleColor::Green, "[+] "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_NEGATIVE(x, ...) clrprintf(ConsoleColor::Red, "[-] "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);

#define PRINT_STATUS(x) clrprintf(ConsoleColor::Blue, "[~] " x " ");
#define PRINT_STATUS_OK clrprintf(ConsoleColor::Green, "[  OK  ]\n");
#define PRINT_STATUS_FAIL clrprintf(ConsoleColor::Red, "[ FAIL ]\n");

#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

unsigned long g_nDataSectionSize = 0x1000;
unsigned long g_nCodeSectionSize = 0x1000;
unsigned long g_nVerboseLevel = 0;

std::tuple<HANDLE, HANDLE, void*> MapFile(const char* fpath) {
	std::tuple<HANDLE, HANDLE, void*> data(nullptr, nullptr, nullptr);

	PRINT_STATUS("Opening file...");
	HANDLE hFile = CreateFileA(fpath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		PRINT_STATUS_FAIL;
		PRINT_ERROR("Unable to open file.");
		return data;
	}
	PRINT_STATUS_OK;

	std::get<0>(data) = hFile;

	PRINT_STATUS("Creating a mapping file...");
	HANDLE hFileMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (hFileMap == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		PRINT_STATUS_FAIL;
		PRINT_ERROR("Unable to create mapping file.");
		return data;
	}
	PRINT_STATUS_OK;

	std::get<1>(data) = hFileMap;

	PRINT_STATUS("Opening the mapping file...")
	void* pMap = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		CloseHandle(hFileMap);
		CloseHandle(hFile);
		PRINT_STATUS_FAIL;
		PRINT_ERROR("Unable to open mapping file.");
		return data;
	}
	PRINT_STATUS_OK;

	std::get<2>(data) = pMap;

	return data;
}

std::tuple<HANDLE, HANDLE, void*> MapNewFile(const char* fpath, DWORD dwNumberOfBytesToMap) {
	std::tuple<HANDLE, HANDLE, void*> data(nullptr, nullptr, nullptr);

	PRINT_STATUS("Creating file...");
	HANDLE hFile = CreateFileA(fpath, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		PRINT_STATUS_FAIL;
		PRINT_ERROR("Unable to create file.");
		return data;
	}
	PRINT_STATUS_OK;

	PRINT_STATUS("Filling file...");
	if (SetFilePointer(hFile, dwNumberOfBytesToMap, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		PRINT_STATUS_FAIL;
		PRINT_ERROR("Unable to set file pointer.");
		return data;
	}

	if (!SetEndOfFile(hFile)) {
		PRINT_STATUS_FAIL;
		PRINT_ERROR("Unable to set end of file.");
		return data;
	}
	PRINT_STATUS_OK;

	std::get<0>(data) = hFile;

	PRINT_STATUS("Creating a mapping file...");
	HANDLE hFileMap = CreateFileMappingA(hFile, nullptr, PAGE_READWRITE, 0, 0, nullptr);
	if (hFileMap == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		PRINT_STATUS_FAIL;
		PRINT_ERROR("Unable to create mapping file.");
		return data;
	}
	PRINT_STATUS_OK;

	std::get<1>(data) = hFileMap;

	PRINT_STATUS("Opening the mapping file...")
	void* pMap = MapViewOfFile(hFileMap, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
	if (!pMap) {
		CloseHandle(hFileMap);
		CloseHandle(hFile);
		PRINT_STATUS_FAIL;
		PRINT_ERROR("Unable to open mapping file.");
		return data;
	}
	PRINT_STATUS_OK;

	std::get<2>(data) = pMap;

	return data;
}

void UnMapFile(std::tuple<HANDLE, HANDLE, void*> data) {
	void* pMap = std::get<2>(data);
	if (!pMap) {
		UnmapViewOfFile(pMap);
	}

	HANDLE hFileMap = std::get<1>(data);
	if (!hFileMap) {
		CloseHandle(hFileMap);
	}

	HANDLE hFile = std::get<0>(data);
	if (!hFile) {
		CloseHandle(hFile);
	}
}

//static inline unsigned long Alignment(unsigned long size, unsigned long alignment, unsigned long address)
//{
//	if (size % alignment == 0) {
//		return address + size;
//	}
//	else {
//		return address + (size / alignment + 1) * alignment;
//	}
//};

std::tuple<void*, unsigned long, unsigned long, unsigned long, unsigned long> AppendNewSection32(/*DWORD nFileSize,*/ void* pMap, const char* szName, DWORD nVirtualSize, DWORD nCharacteristics) {
	PIMAGE_DOS_HEADER dh = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS32 nth = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<unsigned long>(pMap) + dh->e_lfanew);
	PIMAGE_FILE_HEADER pfh = &(nth->FileHeader);
	PIMAGE_OPTIONAL_HEADER32 poh = &(nth->OptionalHeader);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<unsigned long>(pfh) + sizeof(IMAGE_FILE_HEADER) + pfh->SizeOfOptionalHeader);
	
	WORD nNumberOfSections = pfh->NumberOfSections;
	DWORD nSectionAlignment = poh->SectionAlignment;

	PIMAGE_SECTION_HEADER pNewSectionHeader = &pFirstSectionHeader[nNumberOfSections];
	PIMAGE_SECTION_HEADER pLastSectionHeader = &pFirstSectionHeader[nNumberOfSections - 1];

	memset(pNewSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(pNewSectionHeader->Name, szName, 8);
	pNewSectionHeader->Misc.VirtualSize = nVirtualSize;
	pNewSectionHeader->VirtualAddress = P2ALIGNUP(pLastSectionHeader->VirtualAddress + pLastSectionHeader->Misc.VirtualSize, nSectionAlignment);
	pNewSectionHeader->SizeOfRawData = P2ALIGNUP(nVirtualSize, poh->FileAlignment);
	//pNewSectionHeader->PointerToRawData = nFileSize;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	pNewSectionHeader->Characteristics = nCharacteristics;

	pfh->NumberOfSections = nNumberOfSections + 1;
	poh->SizeOfImage = P2ALIGNUP(pNewSectionHeader->VirtualAddress + pNewSectionHeader->Misc.VirtualSize, nSectionAlignment);

	return std::tuple<void*, unsigned long, unsigned long, unsigned long, unsigned long>(reinterpret_cast<void*>(reinterpret_cast<unsigned long>(pMap) + pNewSectionHeader->PointerToRawData), pNewSectionHeader->VirtualAddress, pNewSectionHeader->Misc.VirtualSize, pNewSectionHeader->PointerToRawData, pNewSectionHeader->SizeOfRawData);
}

std::tuple<void*, unsigned long, unsigned long, unsigned long, unsigned long> AppendNewSection64(/*DWORD nFileSize,*/ void* pMap, const char* szName, DWORD nVirtualSize, DWORD nCharacteristics) {
	PIMAGE_DOS_HEADER dh = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS64 nth = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<unsigned long>(pMap) + dh->e_lfanew);
	PIMAGE_FILE_HEADER pfh = &(nth->FileHeader);
	PIMAGE_OPTIONAL_HEADER64 poh = &(nth->OptionalHeader);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<unsigned long>(pfh) + sizeof(IMAGE_FILE_HEADER) + pfh->SizeOfOptionalHeader);

	WORD nNumberOfSections = pfh->NumberOfSections;
	DWORD nSectionAlignment = poh->SectionAlignment;

	PIMAGE_SECTION_HEADER pNewSectionHeader = &pFirstSectionHeader[nNumberOfSections];
	PIMAGE_SECTION_HEADER pLastSectionHeader = &pFirstSectionHeader[nNumberOfSections - 1];

	memset(pNewSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(pNewSectionHeader->Name, szName, 8);
	pNewSectionHeader->Misc.VirtualSize = nVirtualSize;
	pNewSectionHeader->VirtualAddress = P2ALIGNUP(pLastSectionHeader->VirtualAddress + pLastSectionHeader->Misc.VirtualSize, nSectionAlignment);
	pNewSectionHeader->SizeOfRawData = P2ALIGNUP(nVirtualSize, poh->FileAlignment);
	//pNewSectionHeader->PointerToRawData = nFileSize;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	pNewSectionHeader->Characteristics = nCharacteristics;

	pfh->NumberOfSections = nNumberOfSections + 1;
	poh->SizeOfImage = P2ALIGNUP(pNewSectionHeader->VirtualAddress + pNewSectionHeader->Misc.VirtualSize, nSectionAlignment);

	//return std::tuple<void*, unsigned long, unsigned long>(reinterpret_cast<void*>(reinterpret_cast<unsigned long>(pMap) + pNewSectionHeader->PointerToRawData), pNewSectionHeader->SizeOfRawData, pNewSectionHeader->VirtualAddress);
	return std::tuple<void*, unsigned long, unsigned long, unsigned long, unsigned long>(reinterpret_cast<void*>(reinterpret_cast<unsigned long>(pMap) + pNewSectionHeader->PointerToRawData), pNewSectionHeader->VirtualAddress, pNewSectionHeader->Misc.VirtualSize, pNewSectionHeader->PointerToRawData, pNewSectionHeader->SizeOfRawData);
}

/*
static bool symbol_resolver(const char* symbol, uint64_t* value)
{
	// is this the missing symbol "_l1" that we want to handle?
	if (!strcmp(symbol, "_l1")) {
		// put value of this symbol in @value
		*value = 0x1002;
		// we handled this symbol, so return true
		return true;
	}

	return false;
}
*/

std::tuple<bool, std::vector<char>> ReadTextFile(const char* fpath) {

	std::vector<char> data;

	long long fsize = 0;
	struct _stat64 st;
	if (!_stat64(fpath, &st)) {
		fsize = st.st_size;
	}
	else {
		PRINT_ERROR("File not found!");
		return std::tuple<bool, std::vector<char>>(false, data);
	}

	FILE* f = nullptr;
	if (fopen_s(&f, fpath, "rb")) {
		PRINT_ERROR("The file cannot be opened!");
		return std::tuple<bool, std::vector<char>>(false, data);
	}

	std::unique_ptr<char[]> buf(new char[fsize]);
	memset(buf.get(), 0, fsize);

	fread_s(buf.get(), fsize, 1, fsize, f);
	if (ferror(f)) {
		PRINT_ERROR("The file could not be read!");
		return std::tuple<bool, std::vector<char>>(false, data);
	}

	data.reserve(fsize);
	data.insert(data.begin(), buf.get(), buf.get() + fsize);

	return std::tuple<bool, std::vector<char>>(true, data);
}

std::tuple<bool, std::vector<unsigned char>> ReadBinaryFile(const char* fpath) {

	std::vector<unsigned char> data;

	long long fsize = 0;
	struct _stat64 st;
	if (!_stat64(fpath, &st)) {
		fsize = st.st_size;
	}
	else {
		PRINT_ERROR("File not found!");
		return std::tuple<bool, std::vector<unsigned char>>(false, data);
	}

	FILE* f = nullptr;
	if (fopen_s(&f, fpath, "rb")) {
		PRINT_ERROR("The file cannot be opened!");
		return std::tuple<bool, std::vector<unsigned char>>(false, data);
	}

	std::unique_ptr<unsigned char[]> buf(new unsigned char[fsize]);
	memset(buf.get(), 0, fsize);

	fread_s(buf.get(), fsize, 1, fsize, f);
	if (ferror(f)) {
		PRINT_ERROR("The file could not be read!");
		return std::tuple<bool, std::vector<unsigned char>>(false, data);
	}

	data.reserve(fsize);
	data.insert(data.begin(), buf.get(), buf.get() + fsize);

	return std::tuple<bool, std::vector<unsigned char>>(true, data);
}

bool WriteBinaryFile(const char* fpath, std::vector<unsigned char> data) {

	FILE* f = nullptr;
	if (fopen_s(&f, fpath, "wb+")) {
		PRINT_ERROR("The file cannot be opened!");
		return false;
	}

	fwrite(data.data(), 1, data.size(), f);
	if (ferror(f)) {
		PRINT_ERROR("The file could not be write!");
		return false;
	}

	return true;
}

std::vector<unsigned char> Assembly32(unsigned long nBaseAddress, const char* szAsm) {
	std::vector<unsigned char> data;
	ks_engine* ks = nullptr;
	if (ks_open(KS_ARCH_X86, KS_MODE_32, &ks) == KS_ERR_OK) {
		unsigned char* encoding = nullptr;
		size_t encoding_size = 0;
		size_t start_count = 0;
		
		if (ks_asm(ks, szAsm, nBaseAddress, &encoding, &encoding_size, &start_count) != KS_ERR_OK) {
			PRINT_ERROR("Unable to build assembly.");
			return data;
		}

		data.reserve(encoding_size);
		data.insert(data.begin(), encoding, encoding + encoding_size);

		ks_free(encoding);
	}
	return data;
}

std::vector<unsigned char> Assembly64(unsigned long nBaseAddress, const char* szAsm) {
	std::vector<unsigned char> data;
	ks_engine* ks = nullptr;
	if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) == KS_ERR_OK) {
		unsigned char* encoding = nullptr;
		size_t encoding_size = 0;
		size_t start_count = 0;

		if (ks_asm(ks, szAsm, nBaseAddress, &encoding, &encoding_size, &start_count) != KS_ERR_OK) {
			PRINT_ERROR("Unable to build assembly.");
			return data;
		}

		data.reserve(encoding_size);
		data.insert(data.begin(), encoding, encoding + encoding_size);

		ks_free(encoding);
	}
	return data;
}

int main(int argc, char* argv[], char* envp[])
{
	clrprintf(ConsoleColor::White, "RenJack by Ren (zeze839@gmail.com) [Version 1.0.0.0]\n\n");
	
	char szMainFileName[32];
	memset(szMainFileName, 0, sizeof(szMainFileName));
	char szMainFileExt[32];
	memset(szMainFileExt, 0, sizeof(szMainFileExt));

	if (_splitpath_s(argv[0], 0, 0, 0, 0, szMainFileName, sizeof(szMainFileName) - 1, szMainFileExt, sizeof(szMainFileExt) - 1)) {
		PRINT_ERROR("Overflow! #1");
		return -1;
	}

	char szMainFile[64];
	memset(szMainFile, 0, sizeof(szMainFile));
	if (!sprintf_s(szMainFile, sizeof(szMainFile) - 1, "%s%s", szMainFileName, szMainFileExt)) {
		PRINT_ERROR("Overflow! #2");
		return -1;
	}

	if (argc < 2) {
		PRINT_WARNING("Usage: %s [/verbose:<level>] [/bdatasize:<bytes>] [/bcodesize:<bytes>] [/input:<file>] [/payload:<file>] [/savepayload] [/outputpayload:<file>] [/output:<file>]\n", szMainFile);
		return -1;
	}
	else {
		for (int i = 0; i < argc; ++i) {
			const char* arg = argv[i];
			if (!strncmp(arg, "/help", 5) || !strncmp(arg, "/?", 2)) {
				PRINT_WARNING("Usage: %s [/verbose:<level>] [/bdatasize:<bytes>] [/bcodesize:<bytes>] [/input:<file>] [/payload:<file>] [/savepayload] [/outputpayload:<file>] [/output:<file>]\n\n    /verbose:<level> - Verbosity level.\n    /bdatasize - Base `.rxdata` size. (Default: 4096)\n    /bcodesize - Base `.rxcode` size. (Default: 4096)\n    /input:<file> - Input PE executable.\n    /payload:<file> - Input binary (.bin) or assembly file (.asm). (Default: null)\n    /savepayload - Save payload to binary file.\n    /outputpayload - Output payload binary. (Default: The name of the output file with `.bin` extension.)\n    /output:<file> - Output PE executable. (Default: The name of the input file with patch prefix.)\n\n", szMainFile);
				return 0;
			}
		}
	}

	char szInputFile[1024];
	memset(szInputFile, 0, sizeof(szInputFile));
	char szPayloadFile[1024];
	memset(szPayloadFile, 0, sizeof(szPayloadFile));
	bool bPayloadIsAssembly = false;
	bool bSavePayload = false;
	char szOutputPayloadFile[1024];
	memset(szOutputPayloadFile, 0, sizeof(szOutputPayloadFile));
	char szOutputFile[1024];
	memset(szOutputFile, 0, sizeof(szOutputFile));

	for (int i = 0; i < argc; ++i) {
		const char* arg = argv[i];
		if (!strncmp(arg, "/verbose:", 9)) {
			sscanf_s(arg, "/verbose:%lu", &g_nVerboseLevel);
			if (g_nVerboseLevel > 0) {
				PRINT_VERBOSE("The verbosity level is set to `%lu`.", g_nVerboseLevel);
			}
			continue;
		}
		if (!strncmp(arg, "/bdatasize:", 11)) {
			sscanf_s(arg, "/bdatasize:%lu", &g_nDataSectionSize);
			if (g_nVerboseLevel > 0) {
				PRINT_VERBOSE("The size of the sector `.rxdata` is set to %lu bytes.", g_nDataSectionSize);
			}
			continue;
		}
		if (!strncmp(arg, "/bcodesize:", 11)) {
			sscanf_s(arg, "/bcodesize:%lu", &g_nCodeSectionSize);
			if (g_nVerboseLevel > 0) {
				PRINT_VERBOSE("The size of the sector `.rxtext` is set to %lu bytes.", g_nCodeSectionSize);
			}
			continue;
		}
		if (!strncmp(arg, "/input:", 7)) {
			char szFile[1024];
			memset(szFile, 0, sizeof(szFile));
			sscanf_s(arg, "/input:%s", szFile, sizeof(szFile) - 1);
			if (strnlen_s(szFile, sizeof(szFile) - 1) > 0) {
				char szFileExt[32];
				memset(szFileExt, 0, sizeof(szFileExt));
				if (_splitpath_s(szFile, nullptr, 0, nullptr, 0, nullptr, 0, szFileExt, sizeof(szFileExt) - 1)) {
					PRINT_ERROR("Overflow! #3\n");
					return -1;
				}
				if (!strncmp(szFileExt, ".exe", sizeof(szFileExt) - 1)) {
					memcpy_s(szInputFile, sizeof(szInputFile) - 1, szFile, sizeof(szFile) - 1);
					continue;
				}
				else if (!strncmp(szFileExt, ".dll", sizeof(szFileExt) - 1)) {
					memcpy_s(szInputFile, sizeof(szInputFile) - 1, szFile, sizeof(szFile) - 1);
					continue;
				}
				else if (!strncmp(szFileExt, ".sys", sizeof(szFileExt) - 1)) {
					memcpy_s(szInputFile, sizeof(szInputFile) - 1, szFile, sizeof(szFile) - 1);
					continue;
				}
				PRINT_ERROR("Only `.exe`, `.dll`, `.sys` files are allowed for input.\n");
				return -1;
			}
			continue;
		}
		if (!strncmp(arg, "/payload:", 9)) {
			char szFile[1024];
			memset(szFile, 0, sizeof(szFile));
			sscanf_s(arg, "/payload:%s", szFile, sizeof(szFile) - 1);
			if (strnlen_s(szFile, sizeof(szFile) - 1) > 0) {
				char szFileExt[32];
				memset(szFileExt, 0, sizeof(szFileExt));
				if (_splitpath_s(szFile, nullptr, 0, nullptr, 0, nullptr, 0, szFileExt, sizeof(szFileExt) - 1)) {
					PRINT_ERROR("Overflow! #4\n");
					return -1;
				}
				if (!strncmp(szFileExt, ".bin", sizeof(szFileExt) - 1)) {
					memcpy_s(szPayloadFile, sizeof(szPayloadFile) - 1, szFile, sizeof(szFile) - 1);
					continue;
				}
				else if (!strncmp(szFileExt, ".asm", sizeof(szFileExt) - 1)) {
					memcpy_s(szPayloadFile, sizeof(szPayloadFile) - 1, szFile, sizeof(szFile) - 1);
					bPayloadIsAssembly = true;
					continue;
				}
				PRINT_ERROR("Only `.bin`, `.asm` files are allowed for payload input.\n");
				return -1;
			}
			continue;
		}
		if (!strncmp(arg, "/savepayload", 12)) {
			bSavePayload = true;
			continue;
		}
		if (!strncmp(arg, "/outputpayload:", 15)) {
			char szFile[1024];
			memset(szFile, 0, sizeof(szFile));
			sscanf_s(arg, "/outputpayload:%s", szFile, sizeof(szFile) - 1);
			if (strnlen_s(szFile, sizeof(szFile) - 1) > 0) {
				char szFileExt[32];
				memset(szFileExt, 0, sizeof(szFileExt));
				if (_splitpath_s(szFile, nullptr, 0, nullptr, 0, nullptr, 0, szFileExt, sizeof(szFileExt) - 1)) {
					PRINT_ERROR("Overflow! #5\n");
					return -1;
				}
				if (!strncmp(szFileExt, ".bin", sizeof(szFileExt) - 1)) {
					memcpy_s(szOutputPayloadFile, sizeof(szOutputPayloadFile) - 1, szFile, sizeof(szFile) - 1);
					continue;
				}
				PRINT_ERROR("Only `.bin` files are allowed for payload output.\n");
				return -1;
			}
			continue;
		}
		if (!strncmp(arg, "/output:", 8)) {
			char szFile[1024];
			memset(szFile, 0, sizeof(szFile));
			sscanf_s(arg, "/output:%s", szFile, sizeof(szFile) - 1);
			if (strnlen_s(szFile, sizeof(szFile) - 1) > 0) {
				char szFileExt[32];
				memset(szFileExt, 0, sizeof(szFileExt));
				if (_splitpath_s(szFile, nullptr, 0, nullptr, 0, nullptr, 0, szFileExt, sizeof(szFileExt) - 1)) {
					PRINT_ERROR("Overflow! #6\n");
					return -1;
				}
				memcpy_s(szOutputFile, sizeof(szOutputFile) - 1, szFile, sizeof(szFile) - 1);
			}
			continue;
		}
	}

	if (g_nDataSectionSize < 0x1000) {
		PRINT_ERROR("Minimum `.rxdata` size is 4096.");
		return -1;
	}

	if (g_nCodeSectionSize < 0x1000) {
		PRINT_ERROR("Minimum `.rxtext` size is 4096.");
		return -1;
	}

	if (!strnlen_s(szInputFile, sizeof(szInputFile))) {
		PRINT_ERROR("Input file is empty.");
		return -1;
	}
	else {
		PRINT_POSITIVE("Source: %s", szInputFile);
	}

	if (!strnlen_s(szOutputPayloadFile, sizeof(szOutputPayloadFile))) {
		char szDriveFile[256];
		memset(szDriveFile, 0, sizeof(szDriveFile));
		char szDirFile[256];
		memset(szDirFile, 0, sizeof(szDirFile));
		char szFile[256];
		memset(szFile, 0, sizeof(szFile));
		char szFileExt[32];
		memset(szFileExt, 0, sizeof(szFileExt));
		if (_splitpath_s(szPayloadFile, szDriveFile, sizeof(szDriveFile) - 1, szDirFile, sizeof(szDirFile) - 1, szFile, sizeof(szFile) - 1, szFileExt, sizeof(szFileExt) - 1)) {
			PRINT_ERROR("Overflow! #7\n");
			return -1;
		}
		char szBuffer[1024];
		memset(szBuffer, 0, sizeof(szBuffer));
		sprintf_s(szBuffer, "%s%s%s.bin", szDriveFile, szDirFile, szFile, szFileExt);

		memcpy_s(szOutputPayloadFile, sizeof(szOutputPayloadFile) - 1, szBuffer, sizeof(szBuffer) - 1);
	}

	if (!strnlen_s(szOutputFile, sizeof(szOutputFile))) {
		char szDriveFile[256];
		memset(szDriveFile, 0, sizeof(szDriveFile));
		char szDirFile[256];
		memset(szDirFile, 0, sizeof(szDirFile));
		char szFile[256];
		memset(szFile, 0, sizeof(szFile));
		char szFileExt[32];
		memset(szFileExt, 0, sizeof(szFileExt));
		if (_splitpath_s(szInputFile, szDriveFile, sizeof(szDriveFile) - 1, szDirFile, sizeof(szDirFile) - 1, szFile, sizeof(szFile) - 1, szFileExt, sizeof(szFileExt) - 1)) {
			PRINT_ERROR("Overflow! #8\n");
			return -1;
		}
		char szBuffer[1024];
		memset(szBuffer, 0, sizeof(szBuffer));
		sprintf_s(szBuffer, "%s%s%s_rxpatch%s", szDriveFile, szDirFile, szFile, szFileExt);

		memcpy_s(szOutputFile, sizeof(szOutputFile) - 1, szBuffer, sizeof(szBuffer) - 1);
	}

	PRINT_POSITIVE("Target: %s", szOutputFile);

	if (g_nVerboseLevel >= 1) {
		PRINT_VERBOSE("InputFile=\"%s\"", szInputFile);
		if (strnlen_s(szPayloadFile, sizeof(szPayloadFile))) {
			PRINT_VERBOSE("PayloadFile=\"%s\"", szPayloadFile);
		}
		if (strnlen_s(szOutputFile, sizeof(szOutputFile))) {
			PRINT_VERBOSE("OutputFile=\"%s\"", szOutputFile);
		}
	}

	PRINT_INFO("Working with Source...");
	std::tuple<HANDLE, HANDLE, void*> src = MapFile("C:\\Users\\zeze8\\source\\repos\\RenJack\\Release\\FunctionSize.exe");
	
	HANDLE hSrcFile = std::get<0>(src);
	HANDLE hSrcFileMap = std::get<1>(src);
	void* pSrcMap = std::get<2>(src);

	if (!hSrcFile) {
		return -1;
	}

	if (!hSrcFileMap) {
		return -1;
	}

	if (!pSrcMap) {
		return -1;
	}

	if ((*reinterpret_cast<unsigned short*>(pSrcMap)) != 0x5A4D) { // if src[0:2] == 'MZ' {
		PRINT_ERROR("Invalid HEAD signature.");
		return -1;
	}

	DWORD nFileSize = GetFileSize(hSrcFile, nullptr);
	if (nFileSize < 0) {
		PRINT_ERROR("The file is too small.");
		return -1;
	}

	if (nFileSize < sizeof(IMAGE_DOS_HEADER)) {
		PRINT_ERROR("The file is too small.");
		return -1;
	}

	PRINT_POSITIVE("SourceSize: %lu bytes.", nFileSize);

	PIMAGE_DOS_HEADER src_dh = reinterpret_cast<PIMAGE_DOS_HEADER>(std::get<2>(src));
	if (src_dh->e_magic != IMAGE_DOS_SIGNATURE) {
		PRINT_ERROR("Invalid DOS signature.");
		return -1;
	}

	PIMAGE_NT_HEADERS src_nth = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned long>(src_dh) + src_dh->e_lfanew);
	if (src_nth->Signature != IMAGE_NT_SIGNATURE) {
		PRINT_ERROR("Invalid PE signature.");
		return -1;
	}

	HANDLE hDstFile = nullptr;
	HANDLE hDstFileMap = nullptr;
	void* pDstMap = nullptr;

	PIMAGE_FILE_HEADER src_pfh = &(src_nth->FileHeader);
	if (src_pfh->Machine == IMAGE_FILE_MACHINE_I386) {
		PRINT_INFO("Detected 32BIT machine.");
		PIMAGE_OPTIONAL_HEADER32 src_poh = &(src_nth->OptionalHeader);
		if (src_poh->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			PRINT_ERROR("Invalid optional PE signature.");
			return -1;
		}

		PRINT_INFO("Working with Target...");

		DWORD nNewFileSize = P2ALIGNUP(nFileSize + g_nDataSectionSize + g_nCodeSectionSize, src_poh->FileAlignment);
		PRINT_POSITIVE("TargetSize: %lu bytes.", nNewFileSize);

		std::tuple<HANDLE, HANDLE, void*> dst = MapNewFile("C:\\Users\\zeze8\\source\\repos\\RenJack\\Release\\FunctionSize_patched.exe", nNewFileSize);

		hDstFile = std::get<0>(dst);
		hDstFileMap = std::get<1>(dst);
		pDstMap = std::get<2>(dst);

		if (!hDstFile) {
			return -1;
		}

		if (!hDstFileMap) {
			UnMapFile(dst);
			return -1;
		}

		if (!pDstMap) {
			UnMapFile(dst);
			return -1;
		}

		PIMAGE_DOS_HEADER dst_dh = reinterpret_cast<PIMAGE_DOS_HEADER>(pDstMap);
		PIMAGE_NT_HEADERS32 dst_nth = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<unsigned long>(dst_dh) + dst_dh->e_lfanew);
		PIMAGE_OPTIONAL_HEADER32 dst_poh = &(dst_nth->OptionalHeader);

		if (g_nVerboseLevel >= 1) {
			PRINT_VERBOSE("Copying data from Source to Target...")
		}
		memcpy(std::get<2>(dst), std::get<2>(src), nFileSize);
		if (g_nVerboseLevel >= 1) {
			PRINT_VERBOSE("Appending sectors...")
		}

		std::tuple<void*, unsigned long, unsigned long, unsigned long, unsigned long> datasect = AppendNewSection32(/*nFileSize,*/ pDstMap, ".rxdata", g_nDataSectionSize, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
		void* datasect_ptr = std::get<0>(datasect);
		unsigned long datasect_virtualaddress = std::get<1>(datasect);
		unsigned long datasect_virtualsize = std::get<2>(datasect);
		unsigned long datasect_rawaddress = std::get<3>(datasect);
		unsigned long datasect_rawsize = std::get<4>(datasect);

		PRINT_POSITIVE("Section `.rxdata` has been added.");
		PRINT_INFO("ImageAddress:   0x%08X", dst_poh->ImageBase + datasect_virtualaddress);
		PRINT_INFO("VirtualAddress: 0x%08X", datasect_virtualaddress);
		PRINT_INFO("VirtualSize:    0x%08X", datasect_virtualsize);
		PRINT_INFO("RawAddress:     0x%08X", datasect_rawaddress);
		PRINT_INFO("RawSize:        0x%08X", datasect_rawsize);

		memset(datasect_ptr, 0x00 /* NULLs... */, datasect_rawsize);

		std::tuple<void*, unsigned long, unsigned long, unsigned long, unsigned long> codesect = AppendNewSection32(/*nFileSize,*/ pDstMap, ".rxtext", g_nCodeSectionSize, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
		void* codesect_ptr = std::get<0>(codesect);
		unsigned long codesect_virtualaddress = std::get<1>(codesect);
		unsigned long codesect_virtualsize = std::get<2>(codesect);
		unsigned long codesect_rawaddress = std::get<3>(codesect);
		unsigned long codesect_rawsize = std::get<4>(codesect);

		PRINT_POSITIVE("Section `.rxtext` has been added.");
		PRINT_INFO("ImageAddress:   0x%08X", dst_poh->ImageBase + codesect_virtualaddress);
		PRINT_INFO("VirtualAddress: 0x%08X", codesect_virtualaddress);
		PRINT_INFO("VirtualSize:    0x%08X", codesect_virtualsize);
		PRINT_INFO("RawAddress:     0x%08X", codesect_rawaddress);
		PRINT_INFO("RawSize:        0x%08X", codesect_rawsize);

		memset(codesect_ptr, 0x90 /* NOPs... */, codesect_rawsize);

		PRINT_STATUS("Injecting JMP for the original EntryPoint...");
		unsigned char jmpcode[5];
		memset(jmpcode, 0, sizeof(jmpcode));
		jmpcode[0] = 0xE9;
		*reinterpret_cast<unsigned long*>(jmpcode + 1) = dst_poh->AddressOfEntryPoint - (codesect_virtualaddress + codesect_rawsize - sizeof(jmpcode)) - 5;
		memcpy(reinterpret_cast<unsigned char*>(codesect_ptr) + codesect_rawsize - sizeof(jmpcode), jmpcode, sizeof(jmpcode));
		PRINT_STATUS_OK;

		PRINT_STATUS("Changing EntryPoint...");
		dst_poh->AddressOfEntryPoint = codesect_virtualaddress;
		PRINT_STATUS_OK;

		if (strnlen_s(szPayloadFile, sizeof(szPayloadFile))) {
			if (bPayloadIsAssembly) {
				PRINT_POSITIVE("Building and injecting assembly...");
				std::tuple<bool, std::vector<char>> data = ReadTextFile(szPayloadFile);
				bool bIsGood = std::get<0>(data);
				if (bIsGood) {
					std::vector<char> fdata = std::get<1>(data);
					std::vector<unsigned char> asmdata = Assembly32(dst_poh->ImageBase + codesect_virtualaddress, fdata.data());
					if (fdata.size() > codesect_rawsize - sizeof(jmpcode)) {
						PRINT_ERROR("The payload is too large. (Use /bcodesize)");
						return -1;
					}
					memcpy(codesect_ptr, asmdata.data(), asmdata.size());
					
					if (bSavePayload) {
						char szDriveFile[256];
						memset(szDriveFile, 0, sizeof(szDriveFile));
						char szDirFile[256];
						memset(szDirFile, 0, sizeof(szDirFile));
						char szFile[256];
						memset(szFile, 0, sizeof(szFile));
						if (_splitpath_s(szOutputPayloadFile, szDriveFile, sizeof(szDriveFile) - 1, szDirFile, sizeof(szDirFile) - 1, szFile, sizeof(szFile) - 1, nullptr, 0)) {
							PRINT_ERROR("Overflow! #9\n");
							return -1;
						}
						char szBuffer[1024];
						memset(szBuffer, 0, sizeof(szBuffer));
						sprintf_s(szBuffer, "%s%s%s.bin", szDriveFile, szDirFile, szFile);
						if (WriteBinaryFile(szBuffer, asmdata)) {
							PRINT_POSITIVE("Assembled payload saved in \"%s\".", szBuffer);
						}
						else {
							PRINT_WARNING("Unable to save assembled payload in \"%s\"", szBuffer);
						}
					}
				}
			}
			else {
				PRINT_POSITIVE("Injecting Payload...");
				std::tuple<bool, std::vector<unsigned char>> data = ReadBinaryFile(szPayloadFile);
				bool bIsGood = std::get<0>(data);
				if (bIsGood) {
					std::vector<unsigned char> fdata = std::get<1>(data);
					if (fdata.size() > codesect_rawsize - sizeof(jmpcode)) {
						PRINT_ERROR("The payload is too large. (Use /bcodesize)");
						return -1;
					}
					memcpy(codesect_ptr, fdata.data(), fdata.size());
					PRINT_POSITIVE("Injected %lu bytes.", fdata.size());
				}
			}
		}

	}
	else if (src_pfh->Machine == IMAGE_FILE_MACHINE_AMD64) {
		PRINT_INFO("Detected 64BIT machine.");
		PIMAGE_OPTIONAL_HEADER64 src_poh = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&(src_nth->OptionalHeader));
		if (src_poh->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			PRINT_ERROR("Invalid optional PE signature.");
			return -1;
		}

		PRINT_INFO("Working with Target...");

		DWORD nNewFileSize = P2ALIGNUP(nFileSize + g_nDataSectionSize + g_nCodeSectionSize, src_poh->FileAlignment);
		PRINT_POSITIVE("TargetSize: %lu bytes.", nNewFileSize);

		std::tuple<HANDLE, HANDLE, void*> dst = MapNewFile("C:\\Users\\zeze8\\source\\repos\\RenJack\\Release\\FunctionSize_patched.exe", nNewFileSize);

		hDstFile = std::get<0>(dst);
		hDstFileMap = std::get<1>(dst);
		pDstMap = std::get<2>(dst);

		if (!hDstFile) {
			return -1;
		}

		if (!hDstFileMap) {
			UnMapFile(dst);
			return -1;
		}

		if (!pDstMap) {
			UnMapFile(dst);
			return -1;
		}

		PIMAGE_DOS_HEADER dst_dh = reinterpret_cast<PIMAGE_DOS_HEADER>(pDstMap);
		PIMAGE_NT_HEADERS64 dst_nth = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<unsigned long>(dst_dh) + dst_dh->e_lfanew);
		//PIMAGE_FILE_HEADER dst_pfh = &(dst_nth->FileHeader); // Unused
		PIMAGE_OPTIONAL_HEADER64 dst_poh = &(dst_nth->OptionalHeader);

		if (g_nVerboseLevel >= 1) {
			PRINT_VERBOSE("Copying data from Source to Target...")
		}
		memcpy(std::get<2>(dst), std::get<2>(src), nFileSize);
		if (g_nVerboseLevel >= 1) {
			PRINT_VERBOSE("Appending sectors...")
		}

		std::tuple<void*, unsigned long, unsigned long, unsigned long, unsigned long> datasect = AppendNewSection64(/*nFileSize,*/ pDstMap, ".rxdata", g_nDataSectionSize, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
		void* datasect_ptr = std::get<0>(datasect);
		unsigned long datasect_virtualaddress = std::get<1>(datasect);
		unsigned long datasect_virtualsize = std::get<2>(datasect);
		unsigned long datasect_rawaddress = std::get<3>(datasect);
		unsigned long datasect_rawsize = std::get<4>(datasect);

		PRINT_POSITIVE("Section `.rxdata` has been added.");
		PRINT_INFO("ImageAddress:   0x%016llX", dst_poh->ImageBase + datasect_virtualaddress);
		PRINT_INFO("VirtualAddress: 0x%08X", datasect_virtualaddress);
		PRINT_INFO("VirtualSize:    0x%08X", datasect_virtualsize);
		PRINT_INFO("RawAddress:     0x%08X", datasect_rawaddress);
		PRINT_INFO("RawSize:        0x%08X", datasect_rawsize);

		memset(datasect_ptr, 0x00 /* NULLs... */, datasect_rawsize);

		std::tuple<void*, unsigned long, unsigned long, unsigned long, unsigned long> codesect = AppendNewSection64(/*nFileSize,*/ pDstMap, ".rxtext", g_nCodeSectionSize, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
		void* codesect_ptr = std::get<0>(codesect);
		unsigned long codesect_virtualaddress = std::get<1>(codesect);
		unsigned long codesect_virtualsize = std::get<2>(codesect);
		unsigned long codesect_rawaddress = std::get<3>(codesect);
		unsigned long codesect_rawsize = std::get<4>(codesect);

		PRINT_POSITIVE("Section `.rxtext` has been added.");
		PRINT_INFO("ImageAddress:   0x%016llX", dst_poh->ImageBase + codesect_virtualaddress);
		PRINT_INFO("VirtualAddress: 0x%08X", codesect_virtualaddress);
		PRINT_INFO("VirtualSize:    0x%08X", codesect_virtualsize);
		PRINT_INFO("RawAddress:     0x%08X", codesect_rawaddress);
		PRINT_INFO("RawSize:        0x%08X", codesect_rawsize);

		memset(codesect_ptr, 0x90 /* NOPs... */, codesect_rawsize);

		PRINT_STATUS("Injecting JMP for the original EntryPoint...");
		unsigned char jmpcode[5];
		memset(jmpcode, 0, sizeof(jmpcode));
		jmpcode[0] = 0xE9;
		*reinterpret_cast<unsigned long*>(jmpcode + 1) = dst_poh->AddressOfEntryPoint - (codesect_virtualaddress + codesect_rawsize - sizeof(jmpcode)) - 5;
		memcpy(reinterpret_cast<unsigned char*>(codesect_ptr) + codesect_rawsize - sizeof(jmpcode), jmpcode, sizeof(jmpcode));
		PRINT_STATUS_OK;

		PRINT_STATUS("Changing EntryPoint...");
		dst_poh->AddressOfEntryPoint = codesect_virtualaddress;
		PRINT_STATUS_OK;

		if (strnlen_s(szPayloadFile, sizeof(szPayloadFile))) {
			if (bPayloadIsAssembly) {
				PRINT_POSITIVE("Building and injecting assembly...");
				std::tuple<bool, std::vector<char>> data = ReadTextFile(szPayloadFile);
				bool bIsGood = std::get<0>(data);
				if (bIsGood) {
					std::vector<char> fdata = std::get<1>(data);
					std::vector<unsigned char> asmdata = Assembly64(dst_poh->ImageBase + codesect_virtualaddress, fdata.data());
					if (fdata.size() > codesect_rawsize - sizeof(jmpcode)) {
						PRINT_ERROR("The payload is too large. (Use /bcodesize)");
						return -1;
					}
					memcpy(codesect_ptr, asmdata.data(), asmdata.size());
					PRINT_INFO("Assembled and injected %lu bytes.", asmdata.size());

					if (bSavePayload) {
						char szDriveFile[256];
						memset(szDriveFile, 0, sizeof(szDriveFile));
						char szDirFile[256];
						memset(szDirFile, 0, sizeof(szDirFile));
						char szFile[256];
						memset(szFile, 0, sizeof(szFile));
						if (_splitpath_s(szOutputPayloadFile, szDriveFile, sizeof(szDriveFile) - 1, szDirFile, sizeof(szDirFile) - 1, szFile, sizeof(szFile) - 1, nullptr, 0)) {
							PRINT_ERROR("Overflow! #10\n");
							return -1;
						}
						char szBuffer[1024];
						memset(szBuffer, 0, sizeof(szBuffer));
						sprintf_s(szBuffer, "%s%s%s.bin", szDriveFile, szDirFile, szFile);
						if (WriteBinaryFile(szBuffer, asmdata)) {
							PRINT_POSITIVE("Assembled payload saved in \"%s\".", szBuffer);
						}
						else {
							PRINT_WARNING("Unable to save assembled payload in \"%s\"", szBuffer);
						}
					}
				}
			}
			else {
				PRINT_POSITIVE("Injecting Payload...");
				std::tuple<bool, std::vector<unsigned char>> data = ReadBinaryFile(szPayloadFile);
				bool bIsGood = std::get<0>(data);
				if (bIsGood) {
					std::vector<unsigned char> fdata = std::get<1>(data);
					if (fdata.size() > codesect_rawsize - sizeof(jmpcode)) {
						PRINT_ERROR("The payload is too large. (Use /bcodesize)");
						return -1;
					}
					memcpy(codesect_ptr, fdata.data(), fdata.size());
					PRINT_INFO("Injected %lu bytes.", fdata.size());
				}
			}
		}

	}
	else {
		PRINT_ERROR("Unknown architecture.");
		return -1;
	}

	PRINT_POSITIVE("Done!");

	return 0;
}
