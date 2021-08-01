
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
#include <algorithm>
#include <memory>
#include <string>

// Custom
#include "ConsoleUtils.h"
#include "keystone.h"

#ifndef __clang__
#pragma warning(disable: 4477)
#endif

#define PRINT_ERROR(x, ...) clrprintf(ConsoleColor::Red, "[!] Error: "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_WARNING(x, ...) clrprintf(ConsoleColor::DarkYellow, "[!] Warning: "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_VERBOSE(x, ...) clrprintf(ConsoleColor::Magenta, "[*] Verbose: "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_INFO(x, ...) clrprintf(ConsoleColor::Cyan, "[i] "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_POSITIVE(x, ...) clrprintf(ConsoleColor::Green, "[+] "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);
#define PRINT_NEGATIVE(x, ...) clrprintf(ConsoleColor::Red, "[-] "); clrprintf(ConsoleColor::White, x "\n", __VA_ARGS__);

#define PRINT_STATUS(x) clrprintf(ConsoleColor::Blue, "[~] " x " ");
#define PRINT_STATUS_OK clrprintf(ConsoleColor::Green, "[  OK  ]\n");
#define PRINT_STATUS_FAIL clrprintf(ConsoleColor::Red, "[ FAIL ]\n");

DWORD g_unDataSectionSize = 0x1000;
DWORD g_unCodeSectionSize = 0x1000;
DWORD g_unVerboseLevel = 0;

std::tuple<HANDLE, HANDLE, LPVOID> MapFile(const char* fpath) {
	std::tuple<HANDLE, HANDLE, LPVOID> data(nullptr, nullptr, nullptr);

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
	LPVOID pMap = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
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

std::tuple<HANDLE, HANDLE, LPVOID> MapNewFile(const char* fpath, DWORD dwNumberOfBytesToMap) {
	std::tuple<HANDLE, HANDLE, LPVOID> data(nullptr, nullptr, nullptr);

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
	LPVOID pMap = MapViewOfFile(hFileMap, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
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

void UnMapFile(std::tuple<HANDLE, HANDLE, LPVOID> data) {
	LPVOID pMap = std::get<2>(data);
	if (pMap) {
		UnmapViewOfFile(pMap);
	}

	HANDLE hFileMap = std::get<1>(data);
	if (hFileMap) {
		CloseHandle(hFileMap);
	}

	HANDLE hFile = std::get<0>(data);
	if (hFile) {
		CloseHandle(hFile);
	}
}

#ifdef __clang__
#define P2ALIGNUP(x, align) (-(-(x) & -(align)))
#else
static inline DWORD P2ALIGNUP(DWORD unSize, DWORD unAlignment) {
	if (unSize % unAlignment == 0) {
		return unSize;
	}
	else {
		return (unSize / unAlignment + 1) * unAlignment;
	}
};
#endif

std::tuple<LPVOID, DWORD, DWORD, DWORD, DWORD> AppendNewSection32(LPVOID pMap, LPCSTR szName, DWORD unVirtualSize, DWORD unCharacteristics) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<char*>(pMap) + pDH->e_lfanew);
	PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
	PIMAGE_OPTIONAL_HEADER32 pOH = &(pNTHs->OptionalHeader);

	PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(pFH) + sizeof(IMAGE_FILE_HEADER) + pFH->SizeOfOptionalHeader);
	WORD unNumberOfSections = pFH->NumberOfSections;
	DWORD unSectionAlignment = pOH->SectionAlignment;

	PIMAGE_SECTION_HEADER pNewSection = &pFirstSection[unNumberOfSections];
	PIMAGE_SECTION_HEADER pLastSection = &pFirstSection[unNumberOfSections - 1];

	memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(pNewSection->Name, szName, 8);
	pNewSection->Misc.VirtualSize = unVirtualSize;
	pNewSection->VirtualAddress = P2ALIGNUP(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, unSectionAlignment);
	pNewSection->SizeOfRawData = P2ALIGNUP(unVirtualSize, pOH->FileAlignment);
	pNewSection->PointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	pNewSection->Characteristics = unCharacteristics;

	pFH->NumberOfSections = unNumberOfSections + 1;
	pOH->SizeOfImage = P2ALIGNUP(pNewSection->VirtualAddress + pNewSection->Misc.VirtualSize, unSectionAlignment);

	return std::tuple<LPVOID, DWORD, DWORD, DWORD, DWORD>(reinterpret_cast<LPVOID>(reinterpret_cast<char*>(pMap) + pNewSection->PointerToRawData), pNewSection->VirtualAddress, pNewSection->Misc.VirtualSize, pNewSection->PointerToRawData, pNewSection->SizeOfRawData);
}

std::tuple<LPVOID, DWORD, DWORD, DWORD, DWORD> AppendNewSection64(LPVOID pMap, LPCSTR szName, DWORD unVirtualSize, DWORD unCharacteristics) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<char*>(pMap) + pDH->e_lfanew);
	PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
	PIMAGE_OPTIONAL_HEADER64 pOH = &(pNTHs->OptionalHeader);

	PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(pFH) + sizeof(IMAGE_FILE_HEADER) + pFH->SizeOfOptionalHeader);
	WORD unNumberOfSections = pFH->NumberOfSections;
	DWORD unSectionAlignment = pOH->SectionAlignment;

	PIMAGE_SECTION_HEADER pNewSection = &pFirstSection[unNumberOfSections];
	PIMAGE_SECTION_HEADER pLastSection = &pFirstSection[unNumberOfSections - 1];

	memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(pNewSection->Name, szName, 8);
	pNewSection->Misc.VirtualSize = unVirtualSize;
	pNewSection->VirtualAddress = P2ALIGNUP(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, unSectionAlignment);
	pNewSection->SizeOfRawData = P2ALIGNUP(unVirtualSize, pOH->FileAlignment);
	pNewSection->PointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	pNewSection->Characteristics = unCharacteristics;

	pFH->NumberOfSections = unNumberOfSections + 1;
	pOH->SizeOfImage = P2ALIGNUP(pNewSection->VirtualAddress + pNewSection->Misc.VirtualSize, unSectionAlignment);

	return std::tuple<LPVOID, DWORD, DWORD, DWORD, DWORD>(reinterpret_cast<LPVOID>(reinterpret_cast<char*>(pMap) + pNewSection->PointerToRawData), pNewSection->VirtualAddress, pNewSection->Misc.VirtualSize, pNewSection->PointerToRawData, pNewSection->SizeOfRawData);
}

/*
std::vector<std::tuple<ULONGLONG, WORD, std::string>> GetEAT32(LPVOID pMap) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<char*>(pMap) + pDH->e_lfanew);
	PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
	PIMAGE_OPTIONAL_HEADER32 pOH = &(pNTHs->OptionalHeader);

	IMAGE_DATA_DIRECTORY ExportDD = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(pFH) + sizeof(IMAGE_FILE_HEADER) + pFH->SizeOfOptionalHeader);

	std::vector<std::tuple<ULONGLONG, WORD, std::string>> vecData;

	for (DWORD i = 0; i < pFH->NumberOfSections; ++i, ++pFirstSection) {
		if ((ExportDD.VirtualAddress >= pFirstSection->VirtualAddress) && (ExportDD.VirtualAddress < (pFirstSection->VirtualAddress + pFirstSection->Misc.VirtualSize))) {

			DWORD unDelta = pFirstSection->VirtualAddress - pFirstSection->PointerToRawData;

			PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pMap) + ExportDD.VirtualAddress - unDelta);

			PDWORD pFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<char*>(pMap) + pExportDirectory->AddressOfFunctions - unDelta);
			PWORD pOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<char*>(pMap) + pExportDirectory->AddressOfNameOrdinals - unDelta);
			PCHAR* pNames = reinterpret_cast<PCHAR*>(reinterpret_cast<char*>(pMap) + pExportDirectory->AddressOfNames - unDelta);

			for (DWORD j = 0; j < pExportDirectory->NumberOfFunctions; ++j) {
				DWORD unFunction = pFunctions[j];
				if (unFunction == 0) {
					continue;
				}
				for (DWORD l = 0; l < pExportDirectory->NumberOfNames; ++l) {
					if (pOrdinals[l] == j) {
						//PRINT_INFO("Export: 0x%08X   `%s`", unFunction, );
						//std::tuple<DWORD, WORD, std::unique_ptr<char>>()
						vecData.push_back(std::tuple<ULONGLONG, WORD, std::string>(pOH->ImageBase + unFunction, pOrdinals[l], std::string(reinterpret_cast<char*>(pMap) + reinterpret_cast<DWORD>(pNames[l]) - unDelta)));
					}
				}
			}
		}
	}

	return vecData;
}

std::vector<std::tuple<std::string, ULONGLONG, WORD, std::string>> GetIAT32(LPVOID pMap) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS32 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<char*>(pMap) + pDH->e_lfanew);
	PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
	PIMAGE_OPTIONAL_HEADER32 pOH = &(pNTHs->OptionalHeader);

	IMAGE_DATA_DIRECTORY ImportDD = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_DATA_DIRECTORY ImportAddressTableDD = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

	PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(pFH) + sizeof(IMAGE_FILE_HEADER) + pFH->SizeOfOptionalHeader);

	std::vector<std::tuple<std::string, ULONGLONG, WORD, std::string>> vecData;

	for (DWORD i = 0; i < pFH->NumberOfSections; ++i, ++pFirstSection) {
		if ((ImportDD.VirtualAddress >= pFirstSection->VirtualAddress) && (ImportDD.VirtualAddress < (pFirstSection->VirtualAddress + pFirstSection->Misc.VirtualSize))) {
			char* pRawOffset = reinterpret_cast<char*>(pMap) + pFirstSection->PointerToRawData;

			PIMAGE_IMPORT_DESCRIPTOR pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pRawOffset + (ImportDD.VirtualAddress - pFirstSection->VirtualAddress));

			std::vector<PIMAGE_IMPORT_DESCRIPTOR> vecImportDescs;

			for (; pImportDesc->Name != 0; ++pImportDesc) {
				vecImportDescs.push_back(pImportDesc);
			}

			std::sort(vecImportDescs.begin(), vecImportDescs.end(), [](PIMAGE_IMPORT_DESCRIPTOR pA, PIMAGE_IMPORT_DESCRIPTOR pB) {
				DWORD unThunkA = pA->OriginalFirstThunk == 0 ? pA->FirstThunk : pA->OriginalFirstThunk;
				DWORD unThunkB = pB->OriginalFirstThunk == 0 ? pB->FirstThunk : pB->OriginalFirstThunk;
				return unThunkA < unThunkB;
				});

			std::vector<PIMAGE_IMPORT_DESCRIPTOR>::iterator it = vecImportDescs.begin();
			for (ULONGLONG j = 0; it != vecImportDescs.end(); ++it) {

				//PRINT_INFO("> Module: %s", reinterpret_cast<char*>(pRawOffset + (pImportDesc->Name - pFirstSection->VirtualAddress)));

				DWORD unThunk = (*it)->OriginalFirstThunk == 0 ? (*it)->FirstThunk : (*it)->OriginalFirstThunk;
				PIMAGE_THUNK_DATA32 pThunkData = reinterpret_cast<PIMAGE_THUNK_DATA32>(pRawOffset + (unThunk - pFirstSection->VirtualAddress));

				for (; pThunkData->u1.AddressOfData != 0; ++j, ++pThunkData) {
					if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						//PRINT_INFO(" -> 0x%08X   `0x%04X` (Ordinal)", pRawOffset + (pThunkData->u1.Function - pFirstSection->VirtualAddress), pThunkData->u1.Ordinal & 0xFFFF);
						vecData.push_back(std::tuple<std::string, ULONGLONG, WORD, std::string>(std::string(reinterpret_cast<char*>(pRawOffset + ((*it)->Name - pFirstSection->VirtualAddress))), pOH->ImageBase + ImportAddressTableDD.VirtualAddress + j * 8, pThunkData->u1.Ordinal & 0xFFFF, std::string(nullptr)));
					}
					else {
						PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pRawOffset + (pThunkData->u1.AddressOfData - pFirstSection->VirtualAddress));
						//PRINT_INFO(" -> 0x%08X   `%s`", pOH->ImageBase + ImportAddressTableDD.VirtualAddress + j * 8, pImportByName->Name);
						vecData.push_back(std::tuple<std::string, ULONGLONG, WORD, std::string>(std::string(reinterpret_cast<char*>(pRawOffset + ((*it)->Name - pFirstSection->VirtualAddress))), pOH->ImageBase + ImportAddressTableDD.VirtualAddress + j * 8, pThunkData->u1.Ordinal & 0xFFFF, std::string(pImportByName->Name)));
					}
				}

			}
		}
	}

	return vecData;
}

std::vector<std::tuple<ULONGLONG, WORD, std::string>> GetEAT64(LPVOID pMap) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<char*>(pMap) + pDH->e_lfanew);
	PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
	PIMAGE_OPTIONAL_HEADER64 pOH = &(pNTHs->OptionalHeader);

	IMAGE_DATA_DIRECTORY ExportDD = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(pFH) + sizeof(IMAGE_FILE_HEADER) + pFH->SizeOfOptionalHeader);

	std::vector<std::tuple<ULONGLONG, WORD, std::string>> vecData;

	for (DWORD i = 0; i < pFH->NumberOfSections; ++i, ++pFirstSection) {
		if ((ExportDD.VirtualAddress >= pFirstSection->VirtualAddress) && (ExportDD.VirtualAddress < (pFirstSection->VirtualAddress + pFirstSection->Misc.VirtualSize))) {

			DWORD unDelta = pFirstSection->VirtualAddress - pFirstSection->PointerToRawData;

			PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pMap) + ExportDD.VirtualAddress - unDelta);

			PDWORD pFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<char*>(pMap) + pExportDirectory->AddressOfFunctions - unDelta);
			PWORD pOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<char*>(pMap) + pExportDirectory->AddressOfNameOrdinals - unDelta);
			PCHAR* pNames = reinterpret_cast<PCHAR*>(reinterpret_cast<char*>(pMap) + pExportDirectory->AddressOfNames - unDelta);

			for (DWORD j = 0; j < pExportDirectory->NumberOfFunctions; ++j) {
				DWORD unFunction = pFunctions[j];
				if (unFunction == 0) {
					continue;
				}
				for (DWORD l = 0; l < pExportDirectory->NumberOfNames; ++l) {
					if (pOrdinals[l] == j) {
						//PRINT_INFO("Export: 0x%08X   `%s`", unFunction, );
						//std::tuple<DWORD, WORD, std::unique_ptr<char>>()
						vecData.push_back(std::tuple<ULONGLONG, WORD, std::string>(pOH->ImageBase + unFunction, pOrdinals[l], std::string(reinterpret_cast<char*>(pMap) + reinterpret_cast<DWORD>(pNames[l]) - unDelta)));
					}
				}
			}
		}
	}

	return vecData;
}

std::vector<std::tuple<std::string, ULONGLONG, WORD, std::string>> GetIAT64(LPVOID pMap) {
	PIMAGE_DOS_HEADER pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pMap);
	PIMAGE_NT_HEADERS64 pNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<char*>(pMap) + pDH->e_lfanew);
	PIMAGE_FILE_HEADER pFH = &(pNTHs->FileHeader);
	PIMAGE_OPTIONAL_HEADER64 pOH = &(pNTHs->OptionalHeader);

	IMAGE_DATA_DIRECTORY ImportDD = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_DATA_DIRECTORY ImportAddressTableDD = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

	PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(pFH) + sizeof(IMAGE_FILE_HEADER) + pFH->SizeOfOptionalHeader);

	std::vector<std::tuple<std::string, ULONGLONG, WORD, std::string>> vecData;

	for (DWORD i = 0; i < pFH->NumberOfSections; ++i, ++pFirstSection) {
		if ((ImportDD.VirtualAddress >= pFirstSection->VirtualAddress) && (ImportDD.VirtualAddress < (pFirstSection->VirtualAddress + pFirstSection->Misc.VirtualSize))) {
			char* pRawOffset = reinterpret_cast<char*>(pMap) + pFirstSection->PointerToRawData;

			PIMAGE_IMPORT_DESCRIPTOR pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pRawOffset + (ImportDD.VirtualAddress - pFirstSection->VirtualAddress));
			
			std::vector<PIMAGE_IMPORT_DESCRIPTOR> vecImportDescs;
			
			for (; pImportDesc->Name != 0; ++pImportDesc) {
				vecImportDescs.push_back(pImportDesc);
			}

			std::sort(vecImportDescs.begin(), vecImportDescs.end(), [](PIMAGE_IMPORT_DESCRIPTOR pA, PIMAGE_IMPORT_DESCRIPTOR pB) {
				DWORD unThunkA = pA->OriginalFirstThunk == 0 ? pA->FirstThunk : pA->OriginalFirstThunk;
				DWORD unThunkB = pB->OriginalFirstThunk == 0 ? pB->FirstThunk : pB->OriginalFirstThunk;
				return unThunkA < unThunkB;
			});

			std::vector<PIMAGE_IMPORT_DESCRIPTOR>::iterator it = vecImportDescs.begin();
			ULONGLONG i = 0;
			for (ULONGLONG j = 0; it != vecImportDescs.end(); ++it, i += 8) {

				//PRINT_INFO("> Module: %s", reinterpret_cast<char*>(pRawOffset + (pImportDesc->Name - pFirstSection->VirtualAddress)));

				DWORD unThunk = (*it)->OriginalFirstThunk == 0 ? (*it)->FirstThunk : (*it)->OriginalFirstThunk;
				PIMAGE_THUNK_DATA64 pThunkData = reinterpret_cast<PIMAGE_THUNK_DATA64>(pRawOffset + (unThunk - pFirstSection->VirtualAddress));

				for (; pThunkData->u1.AddressOfData != 0; ++j, ++pThunkData) {
					if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						//PRINT_INFO(" -> 0x%08X   `0x%04X` (Ordinal)", pRawOffset + (pThunkData->u1.Function - pFirstSection->VirtualAddress), pThunkData->u1.Ordinal & 0xFFFF);
						vecData.push_back(std::tuple<std::string, ULONGLONG, WORD, std::string>(std::string(reinterpret_cast<char*>(pRawOffset + ((*it)->Name - pFirstSection->VirtualAddress))), pOH->ImageBase + ImportAddressTableDD.VirtualAddress + j * 8 + i, pThunkData->u1.Ordinal & 0xFFFF, std::string(nullptr)));
					}
					else {
						PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pRawOffset + (pThunkData->u1.AddressOfData - pFirstSection->VirtualAddress));
						//PRINT_INFO(" -> 0x%016llX   `%s`", pOH->ImageBase + ImportAddressTableDD.VirtualAddress + j * 8 + i, pImportByName->Name);
						vecData.push_back(std::tuple<std::string, ULONGLONG, WORD, std::string>(std::string(reinterpret_cast<char*>(pRawOffset + ((*it)->Name - pFirstSection->VirtualAddress))), pOH->ImageBase + ImportAddressTableDD.VirtualAddress + j * 8 + i, pThunkData->u1.Ordinal & 0xFFFF, std::string(pImportByName->Name)));
					}
				}

			}
		}
	}

	return vecData;
}

std::vector<std::tuple<ULONGLONG, WORD, std::string>> vecExports;
std::vector<std::tuple<std::string, ULONGLONG, WORD, std::string>> vecImports;

static bool assembly_symbol_resolver(const char* szSymbol, uint64_t* value) {
	if (!strncmp(szSymbol, "export_", 7)) {
		char szExport[1024];
		memset(szExport, 0, sizeof(szExport));
		sscanf_s(szSymbol, "export_%s", szExport, sizeof(szExport) - 1);
		if (strnlen_s(szExport, sizeof(szExport) - 1) > 0) {

			PRINT_STATUS("Finding Export...");

			for (std::vector<std::tuple<ULONGLONG, WORD, std::string>>::iterator it = vecExports.begin(); it != vecExports.end(); ++it) {
				
				ULONGLONG unFunction = std::get<0>(*it);
				std::string strName = std::get<2>(*it);

				if (strName == szExport) {
					PRINT_STATUS_OK;
					*value = unFunction;
					return true;
				}
			}

			PRINT_STATUS_FAIL;
		}
	}

	if (!strncmp(szSymbol, "import_", 7)) {
		char szImport[1024];
		memset(szImport, 0, sizeof(szImport));
		sscanf_s(szSymbol, "import_%s", szImport, sizeof(szImport) - 1);
		if (strnlen_s(szImport, sizeof(szImport) - 1) > 0) {

			PRINT_STATUS("Finding Import...");

			for (std::vector<std::tuple<std::string, ULONGLONG, WORD, std::string>>::iterator it = vecImports.begin(); it != vecImports.end(); ++it) {

				ULONGLONG unFunction = std::get<1>(*it);
				std::string strName = std::get<3>(*it);

				if (strName == szImport) {
					PRINT_STATUS_OK;
					*value = unFunction;
					return true;
				}
			}

			PRINT_STATUS_FAIL;
		}
	}

	return false;
}
*/

std::tuple<bool, std::vector<char>> ReadTextFile(const char* fpath) {

	std::vector<char> data;

	unsigned int fsize = 0;
	struct _stat st;
	if (!_stat(fpath, &st)) {
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

	unsigned int fsize = 0;
	struct _stat st;
	if (!_stat(fpath, &st)) {
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

std::vector<unsigned char> Assembly32(DWORD nBaseAddress, PCHAR szAsm) {
	std::vector<unsigned char> data;
	ks_engine* ks = nullptr;
	if (ks_open(KS_ARCH_X86, KS_MODE_32, &ks) == KS_ERR_OK) {
		//ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(assembly_symbol_resolver));

		unsigned char* encoding = nullptr;
		size_t encoding_size = 0;
		size_t start_count = 0;
		
		if (ks_asm(ks, szAsm, nBaseAddress, &encoding, &encoding_size, &start_count) != KS_ERR_OK) {
			PRINT_ERROR("Unable to build assembly. (err = %d)", ks_errno(ks));
			return data;
		}

		data.reserve(encoding_size);
		data.insert(data.begin(), encoding, encoding + encoding_size);

		ks_free(encoding);
	}
	return data;
}

std::vector<unsigned char> Assembly64(ULONGLONG nBaseAddress, PCHAR szAsm) {
	std::vector<unsigned char> data;
	ks_engine* ks = nullptr;
	if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) == KS_ERR_OK) {
		//ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(assembly_symbol_resolver));

		unsigned char* encoding = nullptr;
		size_t encoding_size = 0;
		size_t start_count = 0;

		if (ks_asm(ks, szAsm, nBaseAddress, &encoding, &encoding_size, &start_count) != KS_ERR_OK) {
			PRINT_ERROR("Unable to build assembly. (err = %d)", ks_errno(ks));
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
	clrprintf(ConsoleColor::White, "RenJack by Ren (zeze839@gmail.com) [Version 1.0.0.1]\n\n");
	
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
		PRINT_WARNING("Usage: %s [/verbose:<level>] [/maxdatasize:<bytes>] [/maxcodesize:<bytes>] [/disabledep] [/disableaslr] [/forceguardcf] [/noentrypoint] [/input:<file>] [/payload:<file>] [/savepayload] [/outputpayload:<file>] [/output:<file>]\n", szMainFile);
		return -1;
	}
	else {
		for (int i = 0; i < argc; ++i) {
			const char* arg = argv[i];
			if (!strncmp(arg, "/help", 5) || !strncmp(arg, "/?", 2)) {
				PRINT_WARNING("Usage: %s [/verbose:<level>] [/maxdatasize:<bytes>] [/maxcodesize:<bytes>] [/disabledep] [/disableaslr] [/forceguardcf] [/noentrypoint] [/input:<file>] [/payload:<file>] [/savepayload] [/outputpayload:<file>] [/output:<file>]\n\n    /verbose:<level> - Verbosity level.\n    /maxdatasize - Maximum `.rxdata` size. (Default: 4096)\n    /maxcodesize - Maximum `.rxtext` size. (Default: 4096)\n    /disabledep - Disables DEP.\n    /disableaslr - Disables ASLR.\n    /forceguardcf - Force processing for GuardCF protected executable.\n    /noentrypoint - No entry point.\n    /input:<file> - Input PE executable.\n    /payload:<file> - Input binary (.bin) or assembly file (.asm). (Default: null)\n    /savepayload - Save payload to binary file.\n    /outputpayload - Output payload binary. (Default: The name of the output file with `.bin` extension.)\n    /output:<file> - Output PE executable. (Default: The name of the input file with patch prefix.)\n\n", szMainFile);
				return 0;
			}
		}
	}

	bool bDisableDEP = false;
	bool bDisableASLR = false;
	bool bForceGuardCF = false;
	bool bNoEntryPoint = false;

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
		const char* szArg = argv[i];
		if (!strncmp(szArg, "/verbose:", 9)) {
			sscanf_s(szArg, "/verbose:%lu", &g_unVerboseLevel);
			if (g_unVerboseLevel > 0) {
				PRINT_VERBOSE("The verbosity level is set to `%lu`.", g_unVerboseLevel);
			}
			continue;
		}
		if (!strncmp(szArg, "/maxdatasize:", 13)) {
			sscanf_s(szArg, "/maxdatasize:%lu", &g_unDataSectionSize);
			if (g_unVerboseLevel > 0) {
				PRINT_VERBOSE("The size of the sector `.rxdata` is set to %lu bytes.", g_unDataSectionSize);
			}
			continue;
		}
		if (!strncmp(szArg, "/maxcodesize:", 13)) {
			sscanf_s(szArg, "/maxcodesize:%lu", &g_unCodeSectionSize);
			if (g_unVerboseLevel > 0) {
				PRINT_VERBOSE("The size of the sector `.rxtext` is set to %lu bytes.", g_unCodeSectionSize);
			}
			continue;
		}
		if (!strncmp(szArg, "/disabledep", 11)) {
			if (g_unVerboseLevel > 0) {
				PRINT_VERBOSE("DEP is disabled.");
			}
			bDisableDEP = true;
			continue;
		}
		if (!strncmp(szArg, "/disableaslr", 12)) {
			if (g_unVerboseLevel > 0) {
				PRINT_VERBOSE("ASLR is disabled.");
			}
			bDisableASLR = true;
			continue;
		}
		if (!strncmp(szArg, "/forceguardcf", 13)) {
			if (g_unVerboseLevel > 0) {
				PRINT_VERBOSE("Enabled force processing for GuardCF protected executable.");
			}
			bForceGuardCF = true;
			continue;
		}
		if (!strncmp(szArg, "/noentrypoint", 13)) {
			if (g_unVerboseLevel > 0) {
				PRINT_VERBOSE("No entry point mode.");
			}
			bNoEntryPoint = true;
			continue;
		}
		if (!strncmp(szArg, "/input:", 7)) {
			char szFile[1024];
			memset(szFile, 0, sizeof(szFile));
			sscanf_s(szArg, "/input:%s", szFile, sizeof(szFile) - 1);
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
		if (!strncmp(szArg, "/payload:", 9)) {
			char szFile[1024];
			memset(szFile, 0, sizeof(szFile));
			sscanf_s(szArg, "/payload:%s", szFile, sizeof(szFile) - 1);
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
		if (!strncmp(szArg, "/savepayload", 12)) {
			bSavePayload = true;
			continue;
		}
		if (!strncmp(szArg, "/outputpayload:", 15)) {
			char szFile[1024];
			memset(szFile, 0, sizeof(szFile));
			sscanf_s(szArg, "/outputpayload:%s", szFile, sizeof(szFile) - 1);
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
		if (!strncmp(szArg, "/output:", 8)) {
			char szFile[1024];
			memset(szFile, 0, sizeof(szFile));
			sscanf_s(szArg, "/output:%s", szFile, sizeof(szFile) - 1);
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

	if (g_unDataSectionSize < 0x1000) {
		PRINT_ERROR("Minimum `.rxdata` size is 4096.");
		return -1;
	}

	if (g_unCodeSectionSize < 0x1000) {
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
		if (_splitpath_s(szPayloadFile, szDriveFile, sizeof(szDriveFile) - 1, szDirFile, sizeof(szDirFile) - 1, szFile, sizeof(szFile) - 1, nullptr, 0)) {
			PRINT_ERROR("Overflow! #7\n");
			return -1;
		}
		char szBuffer[1024];
		memset(szBuffer, 0, sizeof(szBuffer));
		sprintf_s(szBuffer, "%s%s%s.bin", szDriveFile, szDirFile, szFile);

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

	if (g_unVerboseLevel >= 1) {
		PRINT_VERBOSE("InputFile=\"%s\"", szInputFile);
		if (strnlen_s(szPayloadFile, sizeof(szPayloadFile))) {
			PRINT_VERBOSE("PayloadFile=\"%s\"", szPayloadFile);
		}
		if (strnlen_s(szOutputFile, sizeof(szOutputFile))) {
			PRINT_VERBOSE("OutputFile=\"%s\"", szOutputFile);
		}
	}

	PRINT_INFO("Working with Source...");
	std::tuple<HANDLE, HANDLE, LPVOID> src = MapFile(szInputFile);
	
	HANDLE hSrcFile = std::get<0>(src);
	HANDLE hSrcFileMap = std::get<1>(src);
	LPVOID pSrcMap = std::get<2>(src);

	if (!hSrcFile) {
		return -1;
	}

	if (!hSrcFileMap) {
		return -1;
	}

	if (!pSrcMap) {
		return -1;
	}

	DWORD unFileSize = GetFileSize(hSrcFile, nullptr);
	if (unFileSize < 0) {
		PRINT_ERROR("The file is too small.");
		return -1;
	}

	if (unFileSize < sizeof(IMAGE_DOS_HEADER)) {
		PRINT_ERROR("The file is too small.");
		return -1;
	}

	PRINT_POSITIVE("SourceSize: %lu bytes.", unFileSize);

	PIMAGE_DOS_HEADER pSrcDH = reinterpret_cast<PIMAGE_DOS_HEADER>(std::get<2>(src));
	if (pSrcDH->e_magic != IMAGE_DOS_SIGNATURE) {
		PRINT_ERROR("Invalid DOS signature.");
		return -1;
	}

	PIMAGE_NT_HEADERS pSrcNTHs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned char*>(pSrcDH) + pSrcDH->e_lfanew);
	if (pSrcNTHs->Signature != IMAGE_NT_SIGNATURE) {
		PRINT_ERROR("Invalid PE signature.");
		return -1;
	}

	HANDLE hDstFile = nullptr;
	HANDLE hDstFileMap = nullptr;
	LPVOID pDstMap = nullptr;

	PIMAGE_FILE_HEADER pSrcFH = &(pSrcNTHs->FileHeader);
	if (pSrcFH->Machine == IMAGE_FILE_MACHINE_I386) {
		PRINT_INFO("Detected 32BIT machine.");

		//vecExports = GetEAT32(pSrcMap);
		//vecImports = GetIAT32(pSrcMap);

		PIMAGE_OPTIONAL_HEADER32 pSrcOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&(pSrcNTHs->OptionalHeader));
		if (pSrcOH->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			PRINT_ERROR("Invalid optional PE signature.");
			return -1;
		}

		if ((pSrcOH->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) && !bForceGuardCF) {
			PRINT_ERROR("This application is protected from this injection method.");
			return -1;
		}

		PRINT_INFO("Working with Target...");

		DWORD unNewFileSize = P2ALIGNUP(unFileSize + g_unDataSectionSize + g_unCodeSectionSize, pSrcOH->FileAlignment);
		PRINT_POSITIVE("TargetSize: %lu bytes.", unNewFileSize);

		std::tuple<HANDLE, HANDLE, LPVOID> dst = MapNewFile(szOutputFile, unNewFileSize);

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

		PIMAGE_DOS_HEADER pDstDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pDstMap);
		PIMAGE_NT_HEADERS32 pDstNTHs = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<unsigned char*>(pDstDH) + pDstDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER32 pDstOH = &(pDstNTHs->OptionalHeader);

		if (bDisableDEP) {
			pDstOH->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		}

		if (bDisableASLR) {
			pDstOH->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
		}

		if (g_unVerboseLevel >= 1) {
			PRINT_VERBOSE("Copying data from Source to Target...")
		}
		memcpy(std::get<2>(dst), std::get<2>(src), unFileSize);
		if (g_unVerboseLevel >= 1) {
			PRINT_VERBOSE("Appending sectors...")
		}

		std::tuple<LPVOID, DWORD, DWORD, DWORD, DWORD> datasect = AppendNewSection32(pDstMap, ".rxdata", g_unDataSectionSize, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
		LPVOID datasect_ptr = std::get<0>(datasect);
		DWORD datasect_virtualaddress = std::get<1>(datasect);
		DWORD datasect_virtualsize = std::get<2>(datasect);
		DWORD datasect_rawaddress = std::get<3>(datasect);
		DWORD datasect_rawsize = std::get<4>(datasect);

		PRINT_POSITIVE("Section `.rxdata` has been added.");
		PRINT_INFO("ImageAddress:   0x%08X", pDstOH->ImageBase + datasect_virtualaddress);
		PRINT_INFO("VirtualAddress: 0x%08X", datasect_virtualaddress);
		PRINT_INFO("VirtualSize:    0x%08X", datasect_virtualsize);
		PRINT_INFO("RawAddress:     0x%08X", datasect_rawaddress);
		PRINT_INFO("RawSize:        0x%08X", datasect_rawsize);

		memset(datasect_ptr, 0x00 /* NULLs... */, datasect_rawsize);

		std::tuple<LPVOID, DWORD, DWORD, DWORD, DWORD> codesect = AppendNewSection32(pDstMap, ".rxtext", g_unCodeSectionSize, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
		LPVOID codesect_ptr = std::get<0>(codesect);
		DWORD codesect_virtualaddress = std::get<1>(codesect);
		DWORD codesect_virtualsize = std::get<2>(codesect);
		DWORD codesect_rawaddress = std::get<3>(codesect);
		DWORD codesect_rawsize = std::get<4>(codesect);

		PRINT_POSITIVE("Section `.rxtext` has been added.");
		PRINT_INFO("ImageAddress:   0x%08X", pDstOH->ImageBase + codesect_virtualaddress);
		PRINT_INFO("VirtualAddress: 0x%08X", codesect_virtualaddress);
		PRINT_INFO("VirtualSize:    0x%08X", codesect_virtualsize);
		PRINT_INFO("RawAddress:     0x%08X", codesect_rawaddress);
		PRINT_INFO("RawSize:        0x%08X", codesect_rawsize);

		memset(codesect_ptr, 0x90 /* NOPs... */, codesect_rawsize);

		unsigned char jmpcode[5];
		memset(jmpcode, 0, sizeof(jmpcode));

		if (!bNoEntryPoint) {
			PRINT_STATUS("Injecting JMP for the original EntryPoint...");
			jmpcode[0] = 0xE9;
			*reinterpret_cast<DWORD*>(jmpcode + 1) = pDstOH->AddressOfEntryPoint - (codesect_virtualaddress + codesect_rawsize - sizeof(jmpcode)) - 5;
			memcpy(reinterpret_cast<unsigned char*>(codesect_ptr) + codesect_rawsize - sizeof(jmpcode), jmpcode, sizeof(jmpcode));
			PRINT_STATUS_OK;

			PRINT_STATUS("Changing EntryPoint...");
			pDstOH->AddressOfEntryPoint = codesect_virtualaddress;
			PRINT_STATUS_OK;
		}

		if (strnlen_s(szPayloadFile, sizeof(szPayloadFile))) {
			if (bPayloadIsAssembly) {
				PRINT_POSITIVE("Building and injecting assembly...");
				std::tuple<bool, std::vector<char>> data = ReadTextFile(szPayloadFile);
				bool bIsGood = std::get<0>(data);
				if (bIsGood) {
					std::vector<char> fdata = std::get<1>(data);
					std::vector<unsigned char> asmdata = Assembly32(pDstOH->ImageBase + codesect_virtualaddress, fdata.data());
					if (!bNoEntryPoint) {
						if (fdata.size() > codesect_rawsize - sizeof(jmpcode)) {
							PRINT_ERROR("The payload is too large. (Use /maxcodesize)");
							return -1;
						}
					}
					else {
						if (fdata.size() > codesect_rawsize) {
							PRINT_ERROR("The payload is too large. (Use /maxcodesize)");
							return -1;
						}
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
					if (!bNoEntryPoint) {
						if (fdata.size() > codesect_rawsize - sizeof(jmpcode)) {
							PRINT_ERROR("The payload is too large. (Use /maxcodesize)");
							return -1;
						}
					}
					else {
						if (fdata.size() > codesect_rawsize) {
							PRINT_ERROR("The payload is too large. (Use /maxcodesize)");
							return -1;
						}
					}
					memcpy(codesect_ptr, fdata.data(), fdata.size());
					PRINT_POSITIVE("Injected %lu bytes.", fdata.size());
				}
			}
		}

	}
	else if (pSrcFH->Machine == IMAGE_FILE_MACHINE_AMD64) {
		PRINT_INFO("Detected 64BIT machine.");

		//vecExports = GetEAT64(pSrcMap);
		//vecImports = GetIAT64(pSrcMap);

		PIMAGE_OPTIONAL_HEADER64 pSrcOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&(pSrcNTHs->OptionalHeader));
		if (pSrcOH->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			PRINT_ERROR("Invalid optional PE signature.");
			return -1;
		}

		if ((pSrcOH->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) && !bForceGuardCF) {
			PRINT_ERROR("This application is protected from this injection method.");
			return -1;
		}

		PRINT_INFO("Working with Target...");

		DWORD unNewFileSize = P2ALIGNUP(unFileSize + g_unDataSectionSize + g_unCodeSectionSize, pSrcOH->FileAlignment);
		PRINT_POSITIVE("TargetSize: %lu bytes.", unNewFileSize);

		std::tuple<HANDLE, HANDLE, LPVOID> dst = MapNewFile(szOutputFile, unNewFileSize);

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

		PIMAGE_DOS_HEADER pDstDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pDstMap);
		PIMAGE_NT_HEADERS64 pDstNTHs = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<unsigned char*>(pDstDH) + pDstDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER64 pDstOH = &(pDstNTHs->OptionalHeader);

		if (bDisableDEP) {
			pDstOH->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		}

		if (bDisableASLR) {
			pDstOH->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
		}

		if (g_unVerboseLevel >= 1) {
			PRINT_VERBOSE("Copying data from Source to Target...")
		}
		memcpy(std::get<2>(dst), std::get<2>(src), unFileSize);
		if (g_unVerboseLevel >= 1) {
			PRINT_VERBOSE("Appending sectors...")
		}

		std::tuple<LPVOID, DWORD, DWORD, DWORD, DWORD> datasect = AppendNewSection64(pDstMap, ".rxdata", g_unDataSectionSize, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
		LPVOID datasect_ptr = std::get<0>(datasect);
		DWORD datasect_virtualaddress = std::get<1>(datasect);
		DWORD datasect_virtualsize = std::get<2>(datasect);
		DWORD datasect_rawaddress = std::get<3>(datasect);
		DWORD datasect_rawsize = std::get<4>(datasect);

		PRINT_POSITIVE("Section `.rxdata` has been added.");
		PRINT_INFO("ImageAddress:   0x%016llX", pDstOH->ImageBase + datasect_virtualaddress);
		PRINT_INFO("VirtualAddress: 0x%08X", datasect_virtualaddress);
		PRINT_INFO("VirtualSize:    0x%08X", datasect_virtualsize);
		PRINT_INFO("RawAddress:     0x%08X", datasect_rawaddress);
		PRINT_INFO("RawSize:        0x%08X", datasect_rawsize);

		memset(datasect_ptr, 0x00 /* NULLs... */, datasect_rawsize);

		std::tuple<LPVOID, DWORD, DWORD, DWORD, DWORD> codesect = AppendNewSection64(/*unFileSize,*/ pDstMap, ".rxtext", g_unCodeSectionSize, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
		LPVOID codesect_ptr = std::get<0>(codesect);
		DWORD codesect_virtualaddress = std::get<1>(codesect);
		DWORD codesect_virtualsize = std::get<2>(codesect);
		DWORD codesect_rawaddress = std::get<3>(codesect);
		DWORD codesect_rawsize = std::get<4>(codesect);

		PRINT_POSITIVE("Section `.rxtext` has been added.");
		PRINT_INFO("ImageAddress:   0x%016llX", pDstOH->ImageBase + codesect_virtualaddress);
		PRINT_INFO("VirtualAddress: 0x%08X", codesect_virtualaddress);
		PRINT_INFO("VirtualSize:    0x%08X", codesect_virtualsize);
		PRINT_INFO("RawAddress:     0x%08X", codesect_rawaddress);
		PRINT_INFO("RawSize:        0x%08X", codesect_rawsize);

		memset(codesect_ptr, 0x90 /* NOPs... */, codesect_rawsize);

		unsigned char jmpcode[5];
		memset(jmpcode, 0, sizeof(jmpcode));

		if (!bNoEntryPoint) {
			PRINT_STATUS("Injecting JMP for the original EntryPoint...");
			jmpcode[0] = 0xE9;
			*reinterpret_cast<DWORD*>(jmpcode + 1) = pDstOH->AddressOfEntryPoint - (codesect_virtualaddress + codesect_rawsize - sizeof(jmpcode)) - 5;
			memcpy(reinterpret_cast<unsigned char*>(codesect_ptr) + codesect_rawsize - sizeof(jmpcode), jmpcode, sizeof(jmpcode));
			PRINT_STATUS_OK;

			PRINT_STATUS("Changing EntryPoint...");
			pDstOH->AddressOfEntryPoint = codesect_virtualaddress;
			PRINT_STATUS_OK;
		}

		if (strnlen_s(szPayloadFile, sizeof(szPayloadFile))) {
			if (bPayloadIsAssembly) {
				PRINT_POSITIVE("Building and injecting assembly...");
				std::tuple<bool, std::vector<char>> data = ReadTextFile(szPayloadFile);
				bool bIsGood = std::get<0>(data);
				if (bIsGood) {
					std::vector<char> fdata = std::get<1>(data);
					std::vector<unsigned char> asmdata = Assembly64(pDstOH->ImageBase + codesect_virtualaddress, fdata.data());
					if (!bNoEntryPoint) {
						if (fdata.size() > codesect_rawsize - sizeof(jmpcode)) {
							PRINT_ERROR("The payload is too large. (Use /maxcodesize)");
							return -1;
						}
					}
					else {
						if (fdata.size() > codesect_rawsize) {
							PRINT_ERROR("The payload is too large. (Use /maxcodesize)");
							return -1;
						}
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
					if (!bNoEntryPoint) {
						if (fdata.size() > codesect_rawsize - sizeof(jmpcode)) {
							PRINT_ERROR("The payload is too large. (Use /maxcodesize)");
							return -1;
						}
					}
					else {
						if (fdata.size() > codesect_rawsize) {
							PRINT_ERROR("The payload is too large. (Use /maxcodesize)");
							return -1;
						}
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
