#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <iostream>
#include "auth.h"
#include "utils.h"
#include "skCrypt.h"

#pragma comment(lib, "winhttp.lib")

KeyAuthApp app1 = {
    skCrypt("evilspyfak-month"),
    skCrypt("G5fy72RvWX"),
    skCrypt("1.0"),
    skCrypt("https://keyauth.win/api/1.3/")
};

KeyAuthApp app2 = {
    skCrypt("evilspyfak-day"),
    skCrypt("0hiQa92zCs"),
    skCrypt("1.0"),
    skCrypt("https://keyauth.win/api/1.3/")
};

std::string SendRequest(const std::string& url, const std::string& postData) {
    std::string response;
    HINTERNET hSession = WinHttpOpen(L"KeyAuthClient/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(hSession, CharToWString(skCrypt("keyauth.win")).c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", CharToWString(skCrypt("/api/1.3/")).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
    DWORD dataLength = static_cast<DWORD>(postData.length());
    if (!WinHttpSendRequest(hRequest, headers.c_str(), -1L, (LPVOID)postData.c_str(), dataLength, dataLength, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    DWORD bytesRead = 0;
    char buffer[4096];
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

bool InitApp(const KeyAuthApp& app, std::string& sessionId) {
    std::string postData = skCrypt("type=init&name=") + app.name + "&ownerid=" + app.ownerid + "&ver=" + app.version;
    std::string response = SendRequest(app.url, postData);
    if (response.empty()) {
        SetConsoleColor(RED);
        std::cout << (IsRussianLanguage() ? "Ошибка: не удалось подключиться к серверу!\n" : "Error: failed to connect to server!\n");
        return false;
    }
    if (response.find(skCrypt("\"success\":true")) != std::string::npos) {
        size_t sessionPos = response.find(skCrypt("\"sessionid\":\""));
        if (sessionPos != std::string::npos) {
            sessionPos += 12;
            if (response[sessionPos] == '\"') sessionPos++;
            size_t endPos = response.find("\"", sessionPos);
            if (endPos != std::string::npos && endPos > sessionPos) {
                sessionId = response.substr(sessionPos, endPos - sessionPos);
            }
            else {
                sessionId = "";
            }
        }
        return true;
    }
    return false;
}

bool AuthenticateUser(const std::string& key, std::string& sessionId) {
    std::string appSessionId;
    if (InitApp(app1, appSessionId)) {
        std::string postData = skCrypt("type=license&key=") + key + "&name=" + app1.name + "&ownerid=" + app1.ownerid + "&sessionid=" + appSessionId;
        std::string response = SendRequest(app1.url, postData);
        if (response.empty()) {
            SetConsoleColor(RED);
            std::cout << (IsRussianLanguage() ? "Ошибка: не удалось подключиться к серверу!\n" : "Error: failed to connect to server!\n");
            return false;
        }
        if (response.find(skCrypt("\"success\":true")) != std::string::npos) {
            sessionId = appSessionId;
            SetConsoleColor(GREEN);
            std::cout << (IsRussianLanguage() ? "Авторизация успешна (month)!\n" : "Authorization successful (month)!\n");
            return true;
        }
    }

    if (InitApp(app2, appSessionId)) {
        std::string postData = skCrypt("type=license&key=") + key + "&name=" + app2.name + "&ownerid=" + app2.ownerid + "&sessionid=" + appSessionId;
        std::string response = SendRequest(app2.url, postData);
        if (response.empty()) {
            SetConsoleColor(RED);
            std::cout << (IsRussianLanguage() ? "Ошибка: не удалось подключиться к серверу!\n" : "Error: failed to connect to server!\n");
            return false;
        }
        if (response.find(skCrypt("\"success\":true")) != std::string::npos) {
            sessionId = appSessionId;
            SetConsoleColor(GREEN);
            std::cout << (IsRussianLanguage() ? "Авторизация успешна (day)!\n" : "Authorization successful (day)!\n");
            return true;
        }
    }

    SetConsoleColor(RED);
    std::cout << (IsRussianLanguage() ? "Неверный ключ!\n" : "Invalid key!\n");
    return false;
}

bool CheckSession(const std::string& sessionId) {
    for (const auto& app : { app1, app2 }) {
        std::string postData = skCrypt("type=check&sessionid=") + sessionId + "&name=" + app.name + "&ownerid=" + app.ownerid;
        std::string response = SendRequest(app.url, postData);
        if (response.empty()) {
            SetConsoleColor(RED);
            std::cout << (IsRussianLanguage() ? "Ошибка: не удалось проверить сессию!\n" : "Error: failed to check session!\n");
            return false;
        }
        if (response.find(skCrypt("\"success\":true")) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void ReportCrackAttempt(const std::string& key) {
    std::string logMessage = skCrypt("Попытка кряка 1L Spoofer с ключом: ") + key;
    std::string appSessionId;
    for (const auto& app : { app1, app2 }) {
        if (!InitApp(app, appSessionId)) continue;
        std::string postData = skCrypt("type=log&message=") + logMessage + "&name=" + app.name + "&ownerid=" + app.ownerid;
        SendRequest(app.url, postData);
    }
}

void BanKey(const std::string& key) {
    std::string appSessionId;
    for (const auto& app : { app1, app2 }) {
        if (!InitApp(app, appSessionId)) continue;
        std::string postData = skCrypt("type=ban&key=") + key + "&name=" + app.name + "&ownerid=" + app.ownerid;
        SendRequest(app.url, postData);
    }
}