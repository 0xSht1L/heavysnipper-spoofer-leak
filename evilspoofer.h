#pragma once
#include <string>
#include "guard.h"

std::string GetSavedSessionId();
void SaveSessionId(const std::string& sessionid);
void ClearSavedSessionId();
bool AuthenticateUser(const std::string& key, std::string& sessionid);
bool CheckSession(const std::string& sessionid);
void ReportCrackAttempt(const std::string& key);