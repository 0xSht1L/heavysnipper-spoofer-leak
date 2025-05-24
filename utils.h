#pragma once
#include <string>
#include <windows.h>

enum ConsoleColor {
    BLACK = 0,
    BLUE = 1,
    GREEN = 2,
    CYAN = 3,
    RED = 4,
    MAGENTA = 5,
    BROWN = 6,
    LIGHTGRAY = 7,
    DARKGRAY = 8,
    LIGHTBLUE = 9,
    LIGHTGREEN = 10,
    LIGHTCYAN = 11,
    LIGHTRED = 12,
    LIGHTMAGENTA = 13,
    YELLOW = 14,
    WHITE = 15
};

void SetConsoleColor(ConsoleColor color);
std::string GenerateRandomString(int length);
std::string WCHARToString(const WCHAR* wcharStr);
std::wstring CharToWString(const char* str);
void RestoreWallpaper(const std::string& stdWallpaper);
void RestoreKeyboardLayout(const std::string& stdKeyboardLayout);
bool IsRussianLanguage();