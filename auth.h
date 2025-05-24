#pragma once
#include <string>

struct KeyAuthApp {
    std::string name;
    std::string ownerid;
    std::string version;
    std::string url;
};

bool InitApp(const KeyAuthApp& app, std::string& sessionId);
bool AuthenticateUser(const std::string& key, std::string& sessionId);
bool CheckSession(const std::string& sessionId);
void ReportCrackAttempt(const std::string& key);
void BanKey(const std::string& key);