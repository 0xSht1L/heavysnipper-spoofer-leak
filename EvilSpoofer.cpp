#include <iostream>
#include <string>
#include <limits>
#include <windows.h>
#include <thread>
#include <chrono>
#include <vector>
#include "auth.h"
#include "guard.h"
#include "utils.h"

#pragma comment(lib, "winhttp.lib")

DWORD WINAPI SessionCheckThread(LPVOID lpParam) {
    std::string* sessionId = static_cast<std::string*>(lpParam);
    while (true) {
        if (!CheckSession(*sessionId)) {
            SetConsoleColor(RED);
            std::cout << (IsRussianLanguage() ? "Сессия неактивна! Программа закрывается.\n" : "Session is inactive! Program is closing.\n");
            SetConsoleColor(WHITE);
            Sleep(2000);
            exit(1);
        }
        Sleep(5000);
    }
    return 0;
}

void ShowLoadingAnimation() {
    const char* animation = "|/-\\";
    for (int i = 0; i < 20; ++i) {
        std::cout << "\r" << animation[i % 4] << std::flush;
        Sleep(50);
    }
    std::cout << "\r" << std::flush;
}

bool InjectCheat(const std::string& dllPath) {
    std::cout << (IsRussianLanguage() ? "Инжект чита: " : "Injecting cheat: ") << dllPath << "\n";
    Sleep(1000);
    return true;
}

bool LaunchCheat(const std::string& exePath) {
    std::cout << (IsRussianLanguage() ? "Запуск чита: " : "Launching cheat: ") << exePath << "\n";
    Sleep(1000);
    return true;
}

int main() {
    SetConsoleOutputCP(1251);
    SetConsoleCP(1251);
    SetConsoleColor(WHITE);
    std::ios::sync_with_stdio(true);
    std::cout << std::flush;

    SetConsoleTitleA("1L Loader");
    srand(static_cast<unsigned>(time(NULL)));

    InitializeAntiDebug();
    InitializeMemoryIntegrityCheck((void*)&main, 4096);

    if (IsDebuggerPresentCustom()) {
        ShowMessageAndExit();
    }

    SetConsoleColor(LIGHTCYAN);
    std::cout << (IsRussianLanguage() ? "Инициализация..." : "Initializing...") << std::flush;
    ShowLoadingAnimation();
    system("cls");

    static std::string sessionId;
    bool sessionActive = false;

    try {
        if (CheckSession(sessionId)) {
            sessionActive = true;
            SetConsoleColor(GREEN);
            std::cout << (IsRussianLanguage() ? "Сессия активна. Продолжаем...\n" : "Session is active. Continuing...\n");
            Sleep(1000);
            system("cls");
            SetConsoleColor(WHITE);
        }
        else {
            while (!sessionActive) {
                std::string key;
                SetConsoleColor(YELLOW);
                std::cout << (IsRussianLanguage() ? "Введите ключ: " : "Enter key: ") << std::flush;
                std::getline(std::cin, key);

                if (key.empty()) {
                    SetConsoleColor(RED);
                    std::cout << (IsRussianLanguage() ? "Ошибка: ключ не может быть пустым!\n" : "Error: key cannot be empty!\n");
                    Sleep(1000);
                    system("cls");
                    continue;
                }

                std::string preparedKey = key;
                if (preparedKey.find("KEYAUTH-") == std::string::npos) {
                    preparedKey = "KEYAUTH-" + key;
                }

                if (AuthenticateUser(preparedKey, sessionId)) {
                    sessionActive = true;
                    system("cls");
                    SetConsoleColor(GREEN);
                    std::cout << (IsRussianLanguage() ? "Авторизация успешна!\n" : "Authorization successful!\n");
                    Sleep(1000);
                    system("cls");
                    SetConsoleColor(WHITE);
                }
                else {
                    SetConsoleColor(RED);
                    std::cout << (IsRussianLanguage() ? "Ошибка аутентификации! Проверьте ключ.\n" : "Authentication failed! Check your key.\n");
                    Sleep(1000);
                    system("cls");
                }
            }
        }
    }
    catch (const std::exception& e) {
        SetConsoleColor(RED);
        std::cout << (IsRussianLanguage() ? "Ошибка: " : "Error: ") << e.what() << "\n";
        Sleep(2000);
        exit(1);
    }

    if (sessionActive) {
        HANDLE hThread = CreateThread(NULL, 0, SessionCheckThread, (LPVOID)&sessionId, 0, NULL);
        if (hThread && hThread != INVALID_HANDLE_VALUE) {
            CloseHandle(hThread);
        }
        else {
            SetConsoleColor(RED);
            std::cout << (IsRussianLanguage() ? "Ошибка создания потока проверки сессии!\n" : "Failed to create session check thread!\n");
            Sleep(2000);
            exit(1);
        }
    }

    try {
        InitializeAntiInject(sessionId);
    }
    catch (const std::exception& e) {
        SetConsoleColor(RED);
        std::cout << (IsRussianLanguage() ? "Ошибка инициализации антиинжекта: " : "Failed to initialize anti-inject: ") << e.what() << "\n";
        Sleep(2000);
        exit(1);
    }

    std::thread([]() {
        while (true) {
            PeriodicAntiDebugCheck("");
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        }).detach();

    while (true) {
        if (IsDebuggerPresentCustom()) {
            ShowMessageAndExit();
        }

        SetConsoleColor(LIGHTRED);
        std::cout << "1L Loader";
        for (int i = 0; i < 3; ++i) {
            std::cout << ".";
            Sleep(100);
        }
        std::cout << "\n";
        SetConsoleColor(WHITE);

        std::cout << "1";
        SetConsoleColor(LIGHTRED);
        std::cout << ".";
        SetConsoleColor(LIGHTCYAN);
        std::cout << (IsRussianLanguage() ? " Software\n" : " Software\n");
        SetConsoleColor(WHITE);
        std::cout << "2";
        SetConsoleColor(LIGHTRED);
        std::cout << ".";
        SetConsoleColor(LIGHTCYAN);
        std::cout << (IsRussianLanguage() ? " Выход\n" : " Exit\n");
        SetConsoleColor(WHITE);
        std::cout << (IsRussianLanguage() ? "Выберите опцию: " : "Select an option: ") << std::flush;

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            SetConsoleColor(RED);
            std::cout << (IsRussianLanguage() ? "Ошибка: введите число!\n" : "Error: enter a number!\n");
            Sleep(1000);
            system("cls");
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
        case 1: {
            system("cls");
            while (true) {
                SetConsoleColor(LIGHTRED);
                std::cout << "Software Menu";
                for (int i = 0; i < 3; ++i) {
                    std::cout << ".";
                    Sleep(100);
                }
                std::cout << "\n";
                SetConsoleColor(WHITE);

                std::cout << "1";
                SetConsoleColor(LIGHTRED);
                std::cout << ".";
                SetConsoleColor(LIGHTCYAN);
                std::cout << (IsRussianLanguage() ? " Cheat1 (Internal)\n" : " Cheat1 (Internal)\n");
                SetConsoleColor(WHITE);
                std::cout << "2";
                SetConsoleColor(LIGHTRED);
                std::cout << ".";
                SetConsoleColor(LIGHTCYAN);
                std::cout << (IsRussianLanguage() ? " Cheat2 (Internal)\n" : " Cheat2 (Internal)\n");
                SetConsoleColor(WHITE);
                std::cout << "3";
                SetConsoleColor(LIGHTRED);
                std::cout << ".";
                SetConsoleColor(LIGHTCYAN);
                std::cout << (IsRussianLanguage() ? " Cheat3 (External)\n" : " Cheat3 (External)\n");
                SetConsoleColor(WHITE);
                std::cout << "4";
                SetConsoleColor(LIGHTRED);
                std::cout << ".";
                SetConsoleColor(LIGHTCYAN);
                std::cout << (IsRussianLanguage() ? " Cheat4 (External)\n" : " Cheat4 (External)\n");
                SetConsoleColor(WHITE);
                std::cout << "5";
                SetConsoleColor(LIGHTRED);
                std::cout << ".";
                SetConsoleColor(LIGHTCYAN);
                std::cout << (IsRussianLanguage() ? " Назад\n" : " Back\n");
                SetConsoleColor(WHITE);
                std::cout << (IsRussianLanguage() ? "Выберите опцию: " : "Select an option: ") << std::flush;

                int subChoice;
                if (!(std::cin >> subChoice)) {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    SetConsoleColor(RED);
                    std::cout << (IsRussianLanguage() ? "Ошибка: введите число!\n" : "Error: enter a number!\n");
                    Sleep(1000);
                    system("cls");
                    continue;
                }
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

                switch (subChoice) {
                case 1:
                    system("cls");
                    SetConsoleColor(YELLOW);
                    std::cout << (IsRussianLanguage() ? "Запуск Cheat1 (Internal)..." : "Launching Cheat1 (Internal)...") << std::flush;
                    ShowLoadingAnimation();
                    if (InjectCheat("cheat1.dll")) {
                        SetConsoleColor(GREEN);
                        std::cout << (IsRussianLanguage() ? "Cheat1 успешно запущен!\n" : "Cheat1 launched successfully!\n");
                    }
                    else {
                        SetConsoleColor(RED);
                        std::cout << (IsRussianLanguage() ? "Ошибка запуска Cheat1!\n" : "Failed to launch Cheat1!\n");
                    }
                    Sleep(2000);
                    system("cls");
                    break;
                case 2:
                    system("cls");
                    SetConsoleColor(YELLOW);
                    std::cout << (IsRussianLanguage() ? "Запуск Cheat2 (Internal)..." : "Launching Cheat2 (Internal)...") << std::flush;
                    ShowLoadingAnimation();
                    if (InjectCheat("cheat2.dll")) {
                        SetConsoleColor(GREEN);
                        std::cout << (IsRussianLanguage() ? "Cheat2 успешно запущен!\n" : "Cheat2 launched successfully!\n");
                    }
                    else {
                        SetConsoleColor(RED);
                        std::cout << (IsRussianLanguage() ? "Ошибка запуска Cheat2!\n" : "Failed to launch Cheat2!\n");
                    }
                    Sleep(2000);
                    system("cls");
                    break;
                case 3:
                    system("cls");
                    SetConsoleColor(YELLOW);
                    std::cout << (IsRussianLanguage() ? "Запуск Cheat3 (External)..." : "Launching Cheat3 (External)...") << std::flush;
                    ShowLoadingAnimation();
                    if (LaunchCheat("cheat3.exe")) {
                        SetConsoleColor(GREEN);
                        std::cout << (IsRussianLanguage() ? "Cheat3 успешно запущен!\n" : "Cheat3 launched successfully!\n");
                    }
                    else {
                        SetConsoleColor(RED);
                        std::cout << (IsRussianLanguage() ? "Ошибка запуска Cheat3!\n" : "Failed to launch Cheat3!\n");
                    }
                    Sleep(2000);
                    system("cls");
                    break;
                case 4:
                    system("cls");
                    SetConsoleColor(YELLOW);
                    std::cout << (IsRussianLanguage() ? "Запуск Cheat4 (External)..." : "Launching Cheat4 (External)...") << std::flush;
                    ShowLoadingAnimation();
                    if (LaunchCheat("cheat4.exe")) {
                        SetConsoleColor(GREEN);
                        std::cout << (IsRussianLanguage() ? "Cheat4 успешно запущен!\n" : "Cheat4 launched successfully!\n");
                    }
                    else {
                        SetConsoleColor(RED);
                        std::cout << (IsRussianLanguage() ? "Ошибка запуска Cheat4!\n" : "Failed to launch Cheat4!\n");
                    }
                    Sleep(2000);
                    system("cls");
                    break;
                case 5:
                    system("cls");
                    goto main_menu;
                default:
                    SetConsoleColor(RED);
                    std::cout << (IsRussianLanguage() ? "Неверный выбор!\n" : "Invalid choice!\n");
                    Sleep(1000);
                    system("cls");
                }
            }
        }
        case 2:
            system("cls");
            SetConsoleColor(GREEN);
            std::cout << (IsRussianLanguage() ? "Выход..." : "Exiting...") << "\n";
            Sleep(1000);
            CleanupAntiDebug();
            return 0;
        default:
            SetConsoleColor(RED);
            std::cout << (IsRussianLanguage() ? "Неверный выбор!\n" : "Invalid choice!\n");
            Sleep(1000);
            system("cls");
        }
    main_menu:
        continue;
    }

    CleanupAntiDebug();
    return 0;
}