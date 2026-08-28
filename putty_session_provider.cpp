#include "putty_session_provider.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdio>
#include <cwchar>
#include <map>
#include <set>
#include <vector>

namespace
{
const wchar_t kSessionsRegistryPath[] = L"Software\\SimonTatham\\PuTTY\\Sessions";
const wchar_t kDefaultSessionName[] = L"Default Settings";
const char kGeneratedKey[] = "putty_session";
const char kStableIdKey[] = "putty_stable_id";
const char kUnsupportedKey[] = "putty_unsupported";

class RegistryKey
{
  public:
    RegistryKey() = default;
    ~RegistryKey()
    {
        if (key_)
            RegCloseKey(key_);
    }
    RegistryKey(const RegistryKey &) = delete;
    RegistryKey &operator=(const RegistryKey &) = delete;

    HKEY *Receive()
    {
        return &key_;
    }
    HKEY Get() const
    {
        return key_;
    }

  private:
    HKEY key_ = nullptr;
};

class IniSyncLock
{
  public:
    explicit IniSyncLock(const char *iniFileName)
    {
        char fullPath[32768] = {};
        DWORD length = GetFullPathNameA(iniFileName, _countof(fullPath), fullPath, nullptr);
        const char *path = length > 0 && length < _countof(fullPath) ? fullPath : iniFileName;

        unsigned long long hash = 1469598103934665603ULL;
        for (const unsigned char *p = reinterpret_cast<const unsigned char *>(path); *p; ++p)
        {
            unsigned char folded = static_cast<unsigned char>(std::tolower(*p));
            hash ^= folded;
            hash *= 1099511628211ULL;
        }
        char mutexName[64] = {};
        sprintf_s(mutexName, "Local\\tc-putty-sftp-ini-%016llX", hash);
        mutex_ = CreateMutexA(nullptr, FALSE, mutexName);
        if (mutex_)
        {
            DWORD wait = WaitForSingleObject(mutex_, 30000);
            locked_ = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
        }
    }

    ~IniSyncLock()
    {
        if (locked_)
            ReleaseMutex(mutex_);
        if (mutex_)
            CloseHandle(mutex_);
    }

    bool Locked() const
    {
        return locked_;
    }

  private:
    HANDLE mutex_ = nullptr;
    bool locked_ = false;
};

int HexValue(wchar_t c)
{
    if (c >= L'0' && c <= L'9')
        return c - L'0';
    if (c >= L'a' && c <= L'f')
        return c - L'a' + 10;
    if (c >= L'A' && c <= L'F')
        return c - L'A' + 10;
    return -1;
}

bool BytesToWide(const std::string &bytes, UINT codePage, DWORD flags, std::wstring &result)
{
    result.clear();
    if (bytes.empty())
        return true;
    int count = MultiByteToWideChar(codePage, flags, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (count <= 0)
        return false;
    result.resize(static_cast<size_t>(count));
    return MultiByteToWideChar(codePage, flags, bytes.data(), static_cast<int>(bytes.size()), &result[0], count) ==
           count;
}

void AppendEscapedBytes(std::wstring &output, std::string &escapedBytes)
{
    if (escapedBytes.empty())
        return;
    std::wstring decoded;
    if (!BytesToWide(escapedBytes, CP_UTF8, MB_ERR_INVALID_CHARS, decoded) &&
        !BytesToWide(escapedBytes, CP_ACP, 0, decoded))
    {
        for (unsigned char byte : escapedBytes)
            output.push_back(static_cast<wchar_t>(byte));
    }
    else
        output.append(decoded);
    escapedBytes.clear();
}

bool QueryString(HKEY primary, HKEY fallback, const wchar_t *name, std::wstring &value)
{
    HKEY candidates[] = {primary, fallback};
    for (HKEY key : candidates)
    {
        if (!key)
            continue;
        DWORD type = 0;
        DWORD bytes = 0;
        LONG rc = RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes);
        if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || bytes > 32768)
            continue;
        std::vector<wchar_t> buffer(static_cast<size_t>(bytes / sizeof(wchar_t)) + 1, L'\0');
        rc = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(buffer.data()), &bytes);
        if (rc != ERROR_SUCCESS)
            continue;
        buffer.back() = L'\0';
        value.assign(buffer.data());
        if (type == REG_EXPAND_SZ && !value.empty())
        {
            DWORD needed = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
            if (needed > 0 && needed <= 32768)
            {
                std::vector<wchar_t> expanded(needed, L'\0');
                if (ExpandEnvironmentStringsW(value.c_str(), expanded.data(), needed) != 0)
                    value.assign(expanded.data());
            }
        }
        return true;
    }
    value.clear();
    return false;
}

bool QueryDword(HKEY primary, HKEY fallback, const wchar_t *name, DWORD &value)
{
    HKEY candidates[] = {primary, fallback};
    for (HKEY key : candidates)
    {
        if (!key)
            continue;
        DWORD type = 0;
        DWORD bytes = sizeof(value);
        DWORD current = 0;
        LONG rc = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(&current), &bytes);
        if (rc == ERROR_SUCCESS && type == REG_DWORD && bytes == sizeof(current))
        {
            value = current;
            return true;
        }
    }
    return false;
}

bool WideToCodePage(const std::wstring &input, UINT codePage, std::string &output, bool rejectBestFit)
{
    output.clear();
    if (input.empty())
        return true;
    BOOL usedDefault = FALSE;
    DWORD flags = rejectBestFit && codePage != CP_UTF8 ? WC_NO_BEST_FIT_CHARS : 0;
    int count = WideCharToMultiByte(codePage, flags, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr,
                                    rejectBestFit && codePage != CP_UTF8 ? &usedDefault : nullptr);
    if (count <= 0 || usedDefault)
        return false;
    output.resize(static_cast<size_t>(count));
    usedDefault = FALSE;
    int converted = WideCharToMultiByte(codePage, flags, input.data(), static_cast<int>(input.size()), &output[0],
                                        count, nullptr, rejectBestFit && codePage != CP_UTF8 ? &usedDefault : nullptr);
    return converted == count && !usedDefault;
}

std::string StableId(const std::wstring &registryName)
{
    std::string utf8;
    WideToCodePage(registryName, CP_UTF8, utf8, false);
    static const char hex[] = "0123456789ABCDEF";
    std::string encoded("putty:");
    encoded.reserve(6 + utf8.size() * 2);
    for (unsigned char byte : utf8)
    {
        encoded.push_back(hex[byte >> 4]);
        encoded.push_back(hex[byte & 0x0F]);
    }
    return encoded;
}

std::vector<std::string> IniSections(const char *iniFileName)
{
    std::vector<char> buffer(65536, '\0');
    DWORD copied = GetPrivateProfileSectionNamesA(buffer.data(), static_cast<DWORD>(buffer.size()), iniFileName);
    std::vector<std::string> sections;
    if (copied == 0 || copied >= buffer.size() - 2)
        return sections;
    for (const char *p = buffer.data(); *p; p += strlen(p) + 1)
        sections.emplace_back(p);
    return sections;
}

std::string IniValue(const std::string &section, const char *key, const char *iniFileName)
{
    std::vector<char> buffer(32768, '\0');
    GetPrivateProfileStringA(section.c_str(), key, "", buffer.data(), static_cast<DWORD>(buffer.size()), iniFileName);
    return std::string(buffer.data());
}

struct GeneratedState
{
    std::string section;
    std::string stableId;
    std::string fingerprint;
    std::string utf8;
    std::string unixLineBreaks;
    std::string largeFileSupport;
};

struct CaseInsensitiveLess
{
    bool operator()(const std::string &left, const std::string &right) const
    {
        return _stricmp(left.c_str(), right.c_str()) < 0;
    }
};

std::string ToIniDisplayName(const tcputty::SessionProfile &profile)
{
    std::string result;
    if (WideToCodePage(profile.displayName, CP_ACP, result, true) && !result.empty() && result.size() < MAX_PATH)
        return result;

    std::string fallback = "PuTTY session ";
    std::string id = StableId(profile.registryName);
    fallback.append(id.substr(6, std::min<size_t>(16, id.size() - 6)));
    return fallback;
}

std::string ToIniValue(const std::wstring &value)
{
    std::string result;
    WideToCodePage(value, CP_ACP, result, false);
    return result;
}

bool WriteIni(const std::string &section, const char *key, const std::string *value, const char *iniFileName)
{
    return WritePrivateProfileStringA(section.c_str(), key, value ? value->c_str() : nullptr, iniFileName) != FALSE;
}
} // namespace

namespace tcputty
{
std::wstring DecodeSessionName(const std::wstring &registryName)
{
    std::wstring decoded;
    std::string escapedBytes;
    for (size_t i = 0; i < registryName.size(); ++i)
    {
        if (registryName[i] == L'%' && i + 2 < registryName.size())
        {
            int high = HexValue(registryName[i + 1]);
            int low = HexValue(registryName[i + 2]);
            if (high >= 0 && low >= 0)
            {
                escapedBytes.push_back(static_cast<char>((high << 4) | low));
                i += 2;
                continue;
            }
        }
        AppendEscapedBytes(decoded, escapedBytes);
        decoded.push_back(registryName[i]);
    }
    AppendEscapedBytes(decoded, escapedBytes);
    return decoded;
}

bool EnumerateSessions(std::vector<SessionProfile> &sessions, std::wstring *errorMessage)
{
    sessions.clear();
    if (errorMessage)
        errorMessage->clear();

    RegistryKey sessionsKey;
    LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, kSessionsRegistryPath, 0, KEY_READ, sessionsKey.Receive());
    if (rc == ERROR_FILE_NOT_FOUND)
        return true;
    if (rc != ERROR_SUCCESS)
    {
        if (errorMessage)
            *errorMessage = L"Unable to read PuTTY sessions from the current user registry.";
        return false;
    }

    RegistryKey defaultsKey;
    RegOpenKeyExW(sessionsKey.Get(), kDefaultSessionName, 0, KEY_READ, defaultsKey.Receive());

    DWORD subkeyCount = 0;
    DWORD maxNameLength = 0;
    rc = RegQueryInfoKeyW(sessionsKey.Get(), nullptr, nullptr, nullptr, &subkeyCount, &maxNameLength, nullptr, nullptr,
                          nullptr, nullptr, nullptr, nullptr);
    if (rc != ERROR_SUCCESS || subkeyCount > 4096 || maxNameLength > 32767)
    {
        if (errorMessage)
            *errorMessage = L"PuTTY session registry metadata is invalid or too large.";
        return false;
    }

    std::vector<wchar_t> name(static_cast<size_t>(maxNameLength) + 2, L'\0');
    for (DWORD index = 0; index < subkeyCount; ++index)
    {
        DWORD length = static_cast<DWORD>(name.size());
        FILETIME modified = {};
        rc = RegEnumKeyExW(sessionsKey.Get(), index, name.data(), &length, nullptr, nullptr, nullptr, &modified);
        if (rc != ERROR_SUCCESS)
            continue;
        std::wstring registryName(name.data(), length);
        if (_wcsicmp(registryName.c_str(), kDefaultSessionName) == 0)
            continue;

        RegistryKey sessionKey;
        if (RegOpenKeyExW(sessionsKey.Get(), registryName.c_str(), 0, KEY_READ, sessionKey.Receive()) != ERROR_SUCCESS)
            continue;

        SessionProfile profile;
        profile.registryName = registryName;
        profile.displayName = DecodeSessionName(registryName);
        std::wstring protocol;
        QueryString(sessionKey.Get(), defaultsKey.Get(), L"Protocol", protocol);
        QueryString(sessionKey.Get(), defaultsKey.Get(), L"HostName", profile.hostName);
        if ((!protocol.empty() && _wcsicmp(protocol.c_str(), L"ssh") != 0) || profile.hostName.empty())
            continue;
        QueryString(sessionKey.Get(), defaultsKey.Get(), L"UserName", profile.userName);
        QueryString(sessionKey.Get(), defaultsKey.Get(), L"PublicKeyFile", profile.privateKeyFile);
        DWORD port = 22;
        QueryDword(sessionKey.Get(), defaultsKey.Get(), L"PortNumber", port);
        if (port == 0 || port > 65535)
            continue;
        profile.port = static_cast<unsigned short>(port);
        DWORD proxyMethod = 0;
        QueryDword(sessionKey.Get(), defaultsKey.Get(), L"ProxyMethod", proxyMethod);
        profile.hasUnsupportedProxy = proxyMethod != 0;
        sessions.push_back(profile);
    }

    std::sort(sessions.begin(), sessions.end(), [](const SessionProfile &left, const SessionProfile &right) {
        return _wcsicmp(left.displayName.c_str(), right.displayName.c_str()) < 0;
    });
    return true;
}

int SyncSessionsToIni(const char *iniFileName, std::string *errorMessage)
{
    if (errorMessage)
        errorMessage->clear();
    if (!iniFileName || !*iniFileName)
    {
        if (errorMessage)
            *errorMessage = "SFTP plugin INI path is empty.";
        return -1;
    }

    IniSyncLock syncLock(iniFileName);
    if (!syncLock.Locked())
    {
        if (errorMessage)
            *errorMessage = "Timed out while waiting to update PuTTY session sections.";
        return -1;
    }

    std::vector<SessionProfile> sessions;
    std::wstring registryError;
    if (!EnumerateSessions(sessions, &registryError))
    {
        if (errorMessage)
            WideToCodePage(registryError, CP_ACP, *errorMessage, false);
        return -1;
    }

    std::vector<GeneratedState> oldGenerated;
    std::set<std::string, CaseInsensitiveLess> usedNames;
    for (const std::string &section : IniSections(iniFileName))
    {
        if (IniValue(section, kGeneratedKey, iniFileName) == "1")
        {
            GeneratedState state;
            state.section = section;
            state.stableId = IniValue(section, kStableIdKey, iniFileName);
            state.fingerprint = IniValue(section, "fingerprint", iniFileName);
            state.utf8 = IniValue(section, "utf8", iniFileName);
            state.unixLineBreaks = IniValue(section, "unixlinebreaks", iniFileName);
            state.largeFileSupport = IniValue(section, "largefilesupport", iniFileName);
            oldGenerated.push_back(state);
        }
        else
            usedNames.insert(section);
    }

    std::map<std::string, GeneratedState> oldById;
    for (const GeneratedState &state : oldGenerated)
    {
        if (!state.stableId.empty())
            oldById[state.stableId] = state;
        WritePrivateProfileStringA(state.section.c_str(), nullptr, nullptr, iniFileName);
    }

    int written = 0;
    for (const SessionProfile &profile : sessions)
    {
        std::string section = ToIniDisplayName(profile);
        std::string base = section;
        if (usedNames.find(section) != usedNames.end())
            section.append(" [PuTTY]");
        for (unsigned suffix = 2; usedNames.find(section) != usedNames.end(); ++suffix)
        {
            char number[24];
            sprintf_s(number, " [PuTTY %u]", suffix);
            section = base + number;
        }
        usedNames.insert(section);

        std::string stableId = StableId(profile.registryName);
        std::string host = ToIniValue(profile.hostName);
        if (profile.hostName.find(L':') != std::wstring::npos &&
            !(profile.hostName.size() > 1 && profile.hostName.front() == L'[' && profile.hostName.back() == L']'))
            host = "[" + host + "]";
        if (profile.port != 22)
        {
            char port[16];
            sprintf_s(port, ":%u", static_cast<unsigned>(profile.port));
            host.append(port);
        }
        std::string user = ToIniValue(profile.userName);
        std::string keyFile = ToIniValue(profile.privateKeyFile);
        std::string one = "1";
        std::string zero = "0";
        std::string unsupported = "proxy";

        bool ok = WriteIni(section, "server", &host, iniFileName) &&
                  WriteIni(section, kGeneratedKey, &one, iniFileName) &&
                  WriteIni(section, kStableIdKey, &stableId, iniFileName) &&
                  WriteIni(section, "useagent", &zero, iniFileName);
        ok = ok && WriteIni(section, "user", user.empty() ? nullptr : &user, iniFileName);
        ok = ok && WriteIni(section, "privkeyfile", keyFile.empty() ? nullptr : &keyFile, iniFileName);
        ok = ok && WriteIni(section, "pubkeyfile", nullptr, iniFileName);
        ok =
            ok && WriteIni(section, kUnsupportedKey, profile.hasUnsupportedProxy ? &unsupported : nullptr, iniFileName);

        auto previous = oldById.find(stableId);
        if (previous != oldById.end())
        {
            const GeneratedState &state = previous->second;
            if (!state.fingerprint.empty())
                ok = ok && WriteIni(section, "fingerprint", &state.fingerprint, iniFileName);
            if (!state.utf8.empty())
                ok = ok && WriteIni(section, "utf8", &state.utf8, iniFileName);
            if (!state.unixLineBreaks.empty())
                ok = ok && WriteIni(section, "unixlinebreaks", &state.unixLineBreaks, iniFileName);
            if (!state.largeFileSupport.empty())
                ok = ok && WriteIni(section, "largefilesupport", &state.largeFileSupport, iniFileName);
        }
        if (!ok)
        {
            if (errorMessage)
                *errorMessage = "Unable to update generated PuTTY session sections in sftpplug.ini.";
            return -1;
        }
        ++written;
    }
    WritePrivateProfileStringA(nullptr, nullptr, nullptr, iniFileName);
    return written;
}

bool IsGeneratedSession(const char *displayName, const char *iniFileName)
{
    return displayName && iniFileName && IniValue(displayName, kGeneratedKey, iniFileName) == "1";
}

bool HasUnsupportedSettings(const char *displayName, const char *iniFileName)
{
    return displayName && iniFileName && !IniValue(displayName, kUnsupportedKey, iniFileName).empty();
}
} // namespace tcputty
