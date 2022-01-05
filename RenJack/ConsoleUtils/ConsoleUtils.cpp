#include "ConsoleUtils.h"

// General definitions
HWND g_hConsoleWnd = nullptr;

// API
ConsoleUtils::ConsoleUtils() {
	//hConsoleCP = GetConsoleCP();
	//hConsoleOutputCP = GetConsoleOutputCP();
	SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);
	hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	nbgcolor = 0;
	nfgcolor = 0;
	cbgcolor = 0;
	cfgcolor = 0;
}

ConsoleUtils::~ConsoleUtils() {
	//SetConsoleCP(hConsoleCP);
	//SetConsoleOutputCP(hConsoleOutputCP);
}

void ConsoleUtils::RefreshOutputHandle() {
	hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
}

BOOL ConsoleUtils::GetConsoleAttributes(WORD* pwAttributes) {
	CONSOLE_SCREEN_BUFFER_INFO bufinf;
	memset(&bufinf, 0, sizeof(CONSOLE_SCREEN_BUFFER_INFO));
	if (!::GetConsoleScreenBufferInfo(hConsoleOutput, &bufinf)) {
		return FALSE;
	}
	if (pwAttributes) {
		*pwAttributes = bufinf.wAttributes;
	}
	return TRUE;
}

BOOL ConsoleUtils::SetConsoleAttributes(WORD wAttributes) {
	return ::SetConsoleTextAttribute(hConsoleOutput, wAttributes);
}

BOOL ConsoleUtils::GetConsoleCursorPosition(COORD* pdwCursorPosition) {
	CONSOLE_SCREEN_BUFFER_INFO bufinf;
	memset(&bufinf, 0, sizeof(CONSOLE_SCREEN_BUFFER_INFO));
	if (!::GetConsoleScreenBufferInfo(hConsoleOutput, &bufinf)) {
		return FALSE;
	}
	if (pdwCursorPosition) {
		*pdwCursorPosition = bufinf.dwCursorPosition;
	}
	return TRUE;
}
BOOL ConsoleUtils::SetConsoleCursorPosition(COORD dwCursorPosition) {
	return ::SetConsoleCursorPosition(hConsoleOutput, dwCursorPosition);
}

BOOL ConsoleUtils::HideConsoleCursor() {
	CONSOLE_CURSOR_INFO curinf;
	memset(&curinf, 0, sizeof(CONSOLE_CURSOR_INFO));
	if (!::GetConsoleCursorInfo(hConsoleOutput, &curinf)) {
		return FALSE;
	}
	curinf.bVisible = FALSE;
	if (!::SetConsoleCursorInfo(hConsoleOutput, &curinf)) {
		return FALSE;
	}
	return TRUE;
}

BOOL ConsoleUtils::ShowConsoleCursor() {
	CONSOLE_CURSOR_INFO curinf;
	memset(&curinf, 0, sizeof(CONSOLE_CURSOR_INFO));
	if (!::GetConsoleCursorInfo(hConsoleOutput, &curinf)) {
		return FALSE;
	}
	curinf.bVisible = TRUE;
	if (!::SetConsoleCursorInfo(hConsoleOutput, &curinf)) {
		return FALSE;
	}
	return TRUE;
}

BOOL ConsoleUtils::ClearConsole() {
	CONSOLE_SCREEN_BUFFER_INFO bufinf;
	memset(&bufinf, 0, sizeof(CONSOLE_SCREEN_BUFFER_INFO));
	if (!::GetConsoleScreenBufferInfo(hConsoleOutput, &bufinf)) {
		return FALSE;
	}

	SMALL_RECT scrollRect;
	scrollRect.Left = 0;
	scrollRect.Top = 0;
	scrollRect.Right = bufinf.dwSize.X;
	scrollRect.Bottom = bufinf.dwSize.Y;

	COORD scrollTarget;
	scrollTarget.X = 0;
	scrollTarget.Y = -bufinf.dwSize.Y;

	CHAR_INFO fill;
#ifdef UNICODE
	fill.Char.UnicodeChar = L' ';
#else
	fill.Char.AsciiChar = ' ';
#endif
	fill.Attributes = bufinf.wAttributes;

	if (!::ScrollConsoleScreenBuffer(hConsoleOutput, &scrollRect, nullptr, scrollTarget, &fill)) {
		return FALSE;
	}

	bufinf.dwCursorPosition.X = 0;
	bufinf.dwCursorPosition.Y = 0;

	if (!::SetConsoleCursorPosition(hConsoleOutput, bufinf.dwCursorPosition)) {
		return FALSE;
	}

	return TRUE;
}

BOOL ConsoleUtils::SetConsoleColor(unsigned char bgcolor, unsigned char fgcolor) {

	WORD wAttributes = 0;
	if (GetConsoleAttributes(&wAttributes)) {
		if (bgcolor == ConsoleColor::Empty) {
			bgcolor = wAttributes & 0xF0;
		}
		nbgcolor = wAttributes & 0xF0;
		nfgcolor = wAttributes & 0x0F;
	}

	CONSOLE_SCREEN_BUFFER_INFO bufinf;
	memset(&bufinf, 0, sizeof(CONSOLE_SCREEN_BUFFER_INFO));
	if (!::GetConsoleScreenBufferInfo(hConsoleOutput, &bufinf)) {
		return FALSE;
	}

	COORD coord;
	coord.X = 0;
	coord.Y = 0;
	DWORD NumberOfAttrsWritten[2] = { 0 };
	if (!::FillConsoleOutputAttribute(hConsoleOutput, ((bgcolor & 0x0F) << 4) + (fgcolor & 0x0F), bufinf.dwSize.Y * bufinf.dwSize.X, coord, NumberOfAttrsWritten)) {
		return FALSE;
	}

	return SetConsoleAttributes(((bgcolor & 0x0F) << 4) + (fgcolor & 0x0F));
}

BOOL ConsoleUtils::SetConsoleCursorColor(unsigned char bgcolor, unsigned char fgcolor) {
	WORD wAttributes = 0;
	if (GetConsoleAttributes(&wAttributes)) {
		if (bgcolor == ConsoleColor::Empty) {
			bgcolor = wAttributes & 0xF0;
		}
		nbgcolor = wAttributes & 0xF0;
		nfgcolor = wAttributes & 0x0F;
	}
	return SetConsoleAttributes(((bgcolor & 0x0F) << 4) + (fgcolor & 0x0F));
}

BOOL ConsoleUtils::RestoreLastConsoleCursorColor() {
	return SetConsoleCursorColor(nbgcolor, nfgcolor);
}

void ConsoleUtils::GetLastConsoleCursorColor(unsigned char* pbgcolor, unsigned char* pfgcolor) {
	if (pbgcolor) {
		*pbgcolor = nbgcolor;
	}
	if (pfgcolor) {
		*pfgcolor = nfgcolor;
	}
}

BOOL ReopenConsoleIOs() {
	FILE* stream = nullptr;
	freopen_s(&stream, "CONIN$", "r", stdin);
	freopen_s(&stream, "CONOUT$", "w", stdout);
	freopen_s(&stream, "CONOUT$", "w", stderr);
	return TRUE;
}

BOOL ActivateConsole() {
	g_hConsoleWnd = ::GetConsoleWindow();
	if (g_hConsoleWnd) {
		return FALSE;
	}
	if (!AllocConsole()) {
		return FALSE;
	}
	// Reopen IOs
	if (!ReopenConsoleIOs()) {
		return FALSE;
	}
	// Change codepage
	::SetConsoleCP(CP_UTF8);
	::SetConsoleOutputCP(CP_UTF8);
	// Save console window
	g_hConsoleWnd = ::GetConsoleWindow();
	return TRUE;
}

BOOL ReactivateConsole() {
	if (g_hConsoleWnd) {
		// Reopen IOs
		if (!ReopenConsoleIOs()) {
			return FALSE;
		}
		// Change codepage
		::SetConsoleCP(CP_UTF8);
		::SetConsoleOutputCP(CP_UTF8);
		return TRUE;
	}
	return FALSE;
}

BOOL DeactivateConsole() {
	if (g_hConsoleWnd) {
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
		::FreeConsole();
		g_hConsoleWnd = nullptr;
		return TRUE;
	}
	return FALSE;
}

BOOL HideConsole() {
	if (g_hConsoleWnd) {
		return ::ShowWindow(g_hConsoleWnd, SW_HIDE);
	}
	return FALSE;
}

BOOL ShowConsole() {
	if (g_hConsoleWnd) {
		return ::ShowWindow(g_hConsoleWnd, SW_SHOW);
	}
	return FALSE;
}

BOOL IsConsoleVisible() {
	if (g_hConsoleWnd) {
		return ::IsWindowVisible(g_hConsoleWnd) != FALSE;
	}
	return FALSE;
}

int clrprintf(ConsoleColor bgcolor, ConsoleColor fgcolor, char const* const _Format)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(bgcolor, fgcolor)) {
		return -1;
	}
	int ret = printf("%s", _Format);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}

int clrwprintf(ConsoleColor bgcolor, ConsoleColor fgcolor, wchar_t const* const _Format)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(bgcolor, fgcolor)) {
		return -1;
	}
	int ret = wprintf(L"%s", _Format);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}

int clrprintf(ConsoleColor fgcolor, char const* const _Format)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(ConsoleColor::Empty, fgcolor)) {
		return -1;
	}
	int ret = printf("%s", _Format);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}

int clrwprintf(ConsoleColor fgcolor, wchar_t const* const _Format)
{
	ConsoleUtils conutils;
	if (!conutils.SetConsoleCursorColor(ConsoleColor::Empty, fgcolor)) {
		return -1;
	}
	int ret = wprintf(L"%s", _Format);
	if (!conutils.RestoreLastConsoleCursorColor()) {
		return -2;
	}
	return ret;
}