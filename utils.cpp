#include "utils.h"
#include <random>

void SetConsoleColor(ConsoleColor color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
}

std::string GenerateRandomString(int length) {
    const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, characters.size() - 1);

    std::string randomString;
    for (int i = 0; i < length; ++i) {
        randomString += characters[distribution(generator)];
    }
    return randomString;
}

std::string WCHARToString(const WCHAR* wcharStr) {
    int size = WideCharToMultiByte(CP_UTF8, 0, wcharStr, -1, NULL, 0, NULL, NULL);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wcharStr, -1, &result[0], size, NULL, NULL);
    return result;
}

std::wstring CharToWString(const char* str) {
    if (!str) return std::wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (size <= 0) return std::wstring();
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str, -1, &result[0], size);
    return result;
}

void RestoreWallpaper(const std::string& stdWallpaper) {
    SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (PVOID)stdWallpaper.c_str(), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
}

void RestoreKeyboardLayout(const std::string& stdKeyboardLayout) {
    LoadKeyboardLayoutA(stdKeyboardLayout.c_str(), KLF_ACTIVATE);
}

bool IsRussianLanguage() {
    return GetUserDefaultUILanguage() == 0x0419; // 0x0419 Ч код дл€ русского €зыка
}