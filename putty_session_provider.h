#pragma once

#include <string>
#include <vector>

namespace tcputty
{
struct SessionProfile
{
    std::wstring registryName;
    std::wstring displayName;
    std::wstring hostName;
    std::wstring userName;
    std::wstring privateKeyFile;
    unsigned short port = 22;
    bool hasUnsupportedProxy = false;
};

// PuTTY stores session names with %HH escapes. A plus sign is a literal plus,
// unlike application/x-www-form-urlencoded data.
std::wstring DecodeSessionName(const std::wstring &registryName);

// Reads PuTTY's registry data without modifying it. Default Settings is used
// only as a fallback for values missing from an individual session.
bool EnumerateSessions(std::vector<SessionProfile> &sessions, std::wstring *errorMessage = nullptr);

// Mirrors live PuTTY sessions into explicitly marked, generated INI sections
// understood by the existing SFTP plugin. PuTTY registry data remains read-only.
// Runtime values such as a confirmed host fingerprint survive a refresh.
int SyncSessionsToIni(const char *iniFileName, std::string *errorMessage = nullptr);

bool IsGeneratedSession(const char *displayName, const char *iniFileName);
bool HasUnsupportedSettings(const char *displayName, const char *iniFileName);
} // namespace tcputty
