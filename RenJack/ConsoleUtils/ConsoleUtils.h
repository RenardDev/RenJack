#pragma once

#ifndef _CONSOLEUTILS_H_
#define _CONSOLEUTILS_H_

// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

// Enums
enum ConsoleColor : unsigned char
{
	Black = 0,
	DarkBlue = FOREGROUND_BLUE,
	DarkGreen = FOREGROUND_GREEN,
	DarkCyan = FOREGROUND_GREEN | FOREGROUND_BLUE,
	DarkRed = FOREGROUND_RED,
	DarkMagenta = FOREGROUND_RED | FOREGROUND_BLUE,
	DarkYellow = FOREGROUND_RED | FOREGROUND_GREEN,
	DarkGray = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
	Gray = FOREGROUND_INTENSITY,
	Blue = FOREGROUND_INTENSITY | FOREGROUND_BLUE,
	Green = FOREGROUND_INTENSITY | FOREGROUND_GREEN,
	Cyan = FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE,
	Red = FOREGROUND_INTENSITY | FOREGROUND_RED,
	Magenta = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE,
	Yellow = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN,
	White = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
	Empty = 254,
};

// General definitions
extern HWND g_hConsoleWnd;

// API
class ConsoleUtils {
public:
	ConsoleUtils();
	~ConsoleUtils();
	void RefreshOutputHandle();
public:
	BOOL GetConsoleAttributes(WORD* pwAttributes);
	BOOL SetConsoleAttributes(WORD wAttributes);
	BOOL GetConsoleCursorPosition(COORD* pdwCursorPosition);
	BOOL SetConsoleCursorPosition(COORD dwCursorPosition);
	BOOL HideConsoleCursor();
	BOOL ShowConsoleCursor();
	BOOL ClearConsole();
	BOOL SetConsoleColor(unsigned char bgcolor, unsigned char fgcolor);
	BOOL SetConsoleCursorColor(unsigned char bgcolor, unsigned char fgcolor);
	BOOL RestoreLastConsoleCursorColor();
	void GetLastConsoleCursorColor(unsigned char* pbgcolor, unsigned char* pfgcolor);
private:
	//UINT hConsoleCP;
	//UINT hConsoleOutputCP;
	HANDLE hConsoleOutput;
	unsigned char nbgcolor;
	unsigned char nfgcolor;
	COLORREF cbgcolor;
	COLORREF cfgcolor;
};

BOOL ReopenConsoleIOs();
BOOL ActivateConsole();
BOOL ReactivateConsole();
BOOL DeactivateConsole();
BOOL HideConsole();
BOOL ShowConsole();
BOOL IsConsoleVisible();

int clrprintf(ConsoleColor bgcolor, ConsoleColor fgcolor, char const* const _Format);
int clrwprintf(ConsoleColor bgcolor, ConsoleColor fgcolor, wchar_t const* const _Format);
int clrprintf(ConsoleColor fgcolor, char const* const _Format);
int clrwprintf(ConsoleColor fgcolor, wchar_t const* const _Format);

#endif // !_CONSOLEUTILS_H_

// Template API
template <typename... Args>
__forceinline int clrprintf(ConsoleColor bgcolor, ConsoleColor fgcolor, char const* const _Format, Args... args)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(bgcolor, fgcolor)) {
		return -1;
	}
	int ret = printf(_Format, args...);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}

template <typename... Args>
__forceinline int clrprintf(ConsoleColor fgcolor, char const* const _Format, Args... args)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(ConsoleColor::Empty, fgcolor)) {
		return -1;
	}
	int ret = printf(_Format, args...);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}

template <typename... Args>
__forceinline int clrscanf(ConsoleColor fgcolor, char const* const _Format, Args... args)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(ConsoleColor::Empty, fgcolor)) {
		return -1;
	}
	int ret = scanf_s(_Format, args...);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}

template <typename... Args>
__forceinline int clrwprintf(ConsoleColor bgcolor, ConsoleColor fgcolor, wchar_t const* const _Format, Args... args)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(bgcolor, fgcolor)) {
		return -1;
	}
	int ret = wprintf(_Format, args...);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}

template <typename... Args>
__forceinline int clrwprintf(ConsoleColor fgcolor, wchar_t const* const _Format, Args... args)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(ConsoleColor::Empty, fgcolor)) {
		return -1;
	}
	int ret = wprintf(_Format, args...);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}

template <typename... Args>
__forceinline int clrwscanf(ConsoleColor fgcolor, wchar_t const* const _Format, Args... args)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(ConsoleColor::Empty, fgcolor)) {
		return -1;
	}
	int ret = wscanf_s(_Format, args...);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}