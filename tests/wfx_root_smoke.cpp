#include <windows.h>

#include "../fsplugin.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <string>

namespace
{
std::string gUserName;
bool gApprovedHostKey = false;
bool gRequestedUserName = false;
bool gUnexpectedSecretPrompt = false;
bool gConnectionLogged = false;
bool gErrorPrompt = false;
unsigned gProgressCalls = 0;
unsigned gLogCalls = 0;
unsigned gRequestCalls = 0;
int gLastRequestType = -1;
const char *gErrorCategory = "none";
const char *gProgressCategory = "none";
const char *gLogCategory = "none";
std::string gProgressSequence;
std::string gLogSequence;

const char *Classify(const char *message);

std::string SafeLogLabel(const char *message)
{
    std::string text = message ? message : "";
    size_t api = text.find("libssh2_");
    if (api != std::string::npos)
    {
        size_t end = text.find(':', api);
        return text.substr(api, end == std::string::npos ? 48 : std::min<size_t>(end - api, 48));
    }
    if (text.find("Fingerprint error") != std::string::npos)
        return "fingerprint-error";
    return Classify(message);
}

const char *Classify(const char *message)
{
    std::string text = message ? message : "";
    for (char &character : text)
        character = static_cast<char>(tolower(static_cast<unsigned char>(character)));
    if (text.find("loading ssh library") != std::string::npos)
        return "ssh-library-load";
    if (text.find("connecting") != std::string::npos)
        return "server-connect";
    if (text.find("session startup") != std::string::npos)
        return "ssh-handshake";
    if (text.find("login via ssh") != std::string::npos)
        return "ssh-login";
    if (text.find("fingerprint") != std::string::npos)
        return "host-key";
    if (text.find("authentication") != std::string::npos || text.find("auth via") != std::string::npos)
        return "authentication";
    if (text.find("sftp") != std::string::npos)
        return "sftp";
    if (text.find("error") != std::string::npos || text.find("failed") != std::string::npos)
        return "error";
    return "other";
}

int __stdcall ProgressCallback(int, char *sourceName, char *, int)
{
    ++gProgressCalls;
    gProgressCategory = Classify(sourceName);
    if (!gProgressSequence.empty())
        gProgressSequence.push_back(',');
    gProgressSequence.append(gProgressCategory);
    return 0;
}

void __stdcall LogCallback(int, int messageType, char *message)
{
    ++gLogCalls;
    gLogCategory = Classify(message);
    if (!gLogSequence.empty())
        gLogSequence.push_back(',');
    gLogSequence.append(SafeLogLabel(message));
    if (messageType == MSGTYPE_CONNECT || messageType == MSGTYPE_CONNECTCOMPLETE)
        gConnectionLogged = true;
}

BOOL __stdcall RequestCallback(int, int requestType, char *, char *customText, char *returnedText, int maxLength)
{
    ++gRequestCalls;
    gLastRequestType = requestType;
    if (requestType == RT_MsgYesNo)
    {
        gApprovedHostKey = true;
        return TRUE;
    }
    if (requestType == RT_UserName && returnedText && maxLength > 0 && !gUserName.empty())
    {
        strncpy_s(returnedText, static_cast<size_t>(maxLength) + 1, gUserName.c_str(), _TRUNCATE);
        gRequestedUserName = true;
        return TRUE;
    }
    if (requestType == RT_Password || requestType == RT_PasswordFirewall)
        gUnexpectedSecretPrompt = true;
    if (requestType == RT_MsgOK || requestType == RT_MsgOKCancel)
    {
        gErrorPrompt = true;
        std::string text = customText ? customText : "";
        for (char &character : text)
            character = static_cast<char>(tolower(static_cast<unsigned char>(character)));
        if (text.find("given server") != std::string::npos)
            gErrorCategory = "server-connect";
        else if (text.find("initialize ssh2") != std::string::npos)
            gErrorCategory = "ssh-initialize";
        else if (text.find("start ssh session") != std::string::npos)
            gErrorCategory = "ssh-handshake";
        else if (text.find("client certificate") != std::string::npos)
            gErrorCategory = "public-key-auth";
        else if (text.find("private key") != std::string::npos || text.find("ppk") != std::string::npos)
            gErrorCategory = "private-key";
        else if (text.find("sftp session") != std::string::npos)
            gErrorCategory = "sftp-initialize";
        else
            gErrorCategory = "other";
    }
    return FALSE;
}

template <typename T> T Resolve(HMODULE module, const char *name)
{
    return reinterpret_cast<T>(GetProcAddress(module, name));
}

std::wstring ParentDirectory(const std::wstring &path)
{
    size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : path.substr(0, slash);
}
} // namespace

int wmain(int argc, wchar_t **argv)
{
    bool connect = argc == 6 && wcscmp(argv[3], L"--connect-prevalidated") == 0;
    bool expect = argc == 5 && wcscmp(argv[3], L"--expect") == 0;
    if (argc != 3 && !connect && !expect)
    {
        fwprintf(stderr,
                 L"Usage: wfx_root_smoke.exe <sftpplug.wfx64> <test-wincmd.ini> "
                 L"[--expect <session> | --connect-prevalidated <session> <user>]\n");
        return 2;
    }

    HMODULE plugin = LoadLibraryW(argv[1]);
    if (!plugin)
    {
        fwprintf(stderr, L"Unable to load WFX plugin (error %lu).\n", GetLastError());
        return 3;
    }

    using SetDefaultParams = void(__stdcall *)(FsDefaultParamStruct *);
    using Init = int(__stdcall *)(int, tProgressProc, tLogProc, tRequestProc);
    using FindFirst = HANDLE(__stdcall *)(WCHAR *, WIN32_FIND_DATAW *);
    using FindNext = BOOL(__stdcall *)(HANDLE, WIN32_FIND_DATAW *);
    using FindClose = int(__stdcall *)(HANDLE);
    using Disconnect = BOOL(__stdcall *)(char *);

    SetDefaultParams setDefaultParams = Resolve<SetDefaultParams>(plugin, "FsSetDefaultParams");
    Init init = Resolve<Init>(plugin, "FsInit");
    FindFirst findFirst = Resolve<FindFirst>(plugin, "FsFindFirstW");
    FindNext findNext = Resolve<FindNext>(plugin, "FsFindNextW");
    FindClose findClose = Resolve<FindClose>(plugin, "FsFindClose");
    Disconnect disconnect = Resolve<Disconnect>(plugin, "FsDisconnect");
    if (!setDefaultParams || !init || !findFirst || !findNext || !findClose || !disconnect)
    {
        fwprintf(stderr, L"Required WFX exports are missing.\n");
        FreeLibrary(plugin);
        return 4;
    }

    FsDefaultParamStruct defaults = {};
    defaults.size = sizeof(defaults);
    defaults.PluginInterfaceVersionLow = 2;
    defaults.PluginInterfaceVersionHi = 1;
    if (WideCharToMultiByte(CP_ACP, 0, argv[2], -1, defaults.DefaultIniName, MAX_PATH, nullptr, nullptr) == 0)
    {
        fwprintf(stderr, L"The test INI path cannot be represented for the plugin.\n");
        FreeLibrary(plugin);
        return 5;
    }
    setDefaultParams(&defaults);
    if (init(77, ProgressCallback, LogCallback, RequestCallback) != 0)
    {
        fwprintf(stderr, L"FsInit failed.\n");
        FreeLibrary(plugin);
        return 6;
    }

    WCHAR root[] = L"\\";
    WIN32_FIND_DATAW data = {};
    HANDLE search = findFirst(root, &data);
    if (search == INVALID_HANDLE_VALUE)
    {
        fwprintf(stderr, L"Root listing failed (error %lu).\n", GetLastError());
        FreeLibrary(plugin);
        return 7;
    }

    unsigned entries = 1;
    unsigned liveSessions = 0;
    bool foundExpected = !connect && !expect;
    while (findNext(search, &data))
    {
        ++entries;
        ++liveSessions;
        if ((connect || expect) && wcscmp(data.cFileName, argv[4]) == 0)
            foundExpected = true;
    }
    findClose(search);

#ifdef _WIN64
    std::wstring libraryPath = ParentDirectory(argv[1]) + L"\\64\\libssh2.dll";
#else
    std::wstring libraryPath = ParentDirectory(argv[1]) + L"\\libssh2.dll";
#endif
    HMODULE libssh2 = LoadLibraryW(libraryPath.c_str());
    using Version = const char *(__cdecl *)(int);
    Version version = libssh2 ? Resolve<Version>(libssh2, "libssh2_version") : nullptr;
    FARPROC fromMemory = libssh2 ? GetProcAddress(libssh2, "libssh2_userauth_publickey_frommemory") : nullptr;
    const char *versionText = version ? version(0) : nullptr;

    bool transportOk = libssh2 && versionText && fromMemory;
    printf("WFX root smoke passed: %u root connection(s), expected=%s, libssh2=%s, frommemory=%s.\n", liveSessions,
           connect || expect ? (foundExpected ? "yes" : "no") : "n/a", versionText ? versionText : "missing",
           fromMemory ? "yes" : "no");

    bool connectOk = true;
    if (connect)
    {
        char userBuffer[256] = {};
        connectOk = WideCharToMultiByte(CP_ACP, 0, argv[5], -1, userBuffer, sizeof(userBuffer), nullptr, nullptr) > 0;
        gUserName.assign(userBuffer);

        std::wstring remote = L"\\";
        remote.append(argv[4]);
        remote.push_back(L'\\');
        WIN32_FIND_DATAW remoteData = {};
        HANDLE remoteSearch = connectOk ? findFirst(&remote[0], &remoteData) : INVALID_HANDLE_VALUE;
        connectOk = connectOk && remoteSearch != INVALID_HANDLE_VALUE;
        if (remoteSearch != INVALID_HANDLE_VALUE)
        {
            findClose(remoteSearch);
            char disconnectRoot[512] = "\\";
            char sessionName[500] = {};
            WideCharToMultiByte(CP_ACP, 0, argv[4], -1, sessionName, sizeof(sessionName), nullptr, nullptr);
            strcat_s(disconnectRoot, sessionName);
            disconnect(disconnectRoot);
        }
        connectOk = connectOk && gConnectionLogged && gRequestedUserName && !gUnexpectedSecretPrompt && !gErrorPrompt;
        printf("WFX connection smoke: authenticated=%s, username-request=%s, host-key-check=%s, secret-prompt=%s, "
               "error-prompt=%s/%s, requests=%u/%d, progress=%u/%s, logs=%u/%s.\n",
               connectOk ? "yes" : "no", gRequestedUserName ? "yes" : "no",
               gApprovedHostKey ? "confirmed" : "already-known", gUnexpectedSecretPrompt ? "unexpected" : "none",
               gErrorPrompt ? "yes" : "no", gErrorCategory, gRequestCalls, gLastRequestType, gProgressCalls,
               gProgressCategory, gLogCalls, gLogCategory);
        printf("WFX callback stages: progress=[%s], logs=[%s].\n", gProgressSequence.c_str(), gLogSequence.c_str());
    }

    if (libssh2)
        FreeLibrary(libssh2);
    FreeLibrary(plugin);
    return entries > 1 && liveSessions > 0 && foundExpected && transportOk && connectOk ? 0 : 8;
}
