#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "../ppk_v3_rsa.h"
#include "../putty_session_provider.h"
#include "../third_party/libssh2/include/libssh2.h"
#include "../third_party/libssh2/include/libssh2_sftp.h"

#include <cstdio>
#include <string>
#include <vector>

namespace
{
template <typename T> T Resolve(HMODULE module, const char *name)
{
    return reinterpret_cast<T>(GetProcAddress(module, name));
}

std::string ToAnsi(const std::wstring &value)
{
    if (value.empty())
        return {};
    int bytes = WideCharToMultiByte(CP_ACP, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0)
        return {};
    std::string result(static_cast<size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_ACP, 0, value.data(), static_cast<int>(value.size()), &result[0], bytes, nullptr,
                            nullptr) != bytes)
        result.clear();
    return result;
}

class SocketGuard
{
  public:
    ~SocketGuard()
    {
        if (socket != INVALID_SOCKET)
            closesocket(socket);
    }
    SOCKET socket = INVALID_SOCKET;
};
} // namespace

int wmain(int argc, wchar_t **argv)
{
    if (argc != 6 || wcscmp(argv[3], L"--host-prevalidated-by-putty") != 0)
    {
        fwprintf(stderr,
                 L"Usage: libssh2_ppk_integration.exe <libssh2.dll> <session> "
                 L"--host-prevalidated-by-putty <user> <ppk>\n");
        return 2;
    }

    std::vector<tcputty::SessionProfile> profiles;
    if (!tcputty::EnumerateSessions(profiles))
        return 3;
    const tcputty::SessionProfile *profile = nullptr;
    for (const auto &candidate : profiles)
    {
        if (_wcsicmp(candidate.displayName.c_str(), argv[2]) == 0)
        {
            profile = &candidate;
            break;
        }
    }
    if (!profile || profile->hasUnsupportedProxy)
        return 4;

    char user[256] = {};
    char keyPath[MAX_PATH] = {};
    if (WideCharToMultiByte(CP_ACP, 0, argv[4], -1, user, sizeof(user), nullptr, nullptr) <= 0 ||
        WideCharToMultiByte(CP_ACP, 0, argv[5], -1, keyPath, sizeof(keyPath), nullptr, nullptr) <= 0)
        return 5;

    tcputty::MemoryKey memoryKey;
    std::string keyError;
    if (tcputty::LoadPpkV3Rsa(keyPath, memoryKey, keyError) != tcputty::PpkLoadResult::Success)
        return 6;

    HMODULE module = LoadLibraryW(argv[1]);
    if (!module)
        return 7;
    using Init = int(__cdecl *)(int);
    using Exit = void(__cdecl *)();
    using SessionInit = LIBSSH2_SESSION *(__cdecl *)(LIBSSH2_ALLOC_FUNC((*)), LIBSSH2_FREE_FUNC((*)),
                                                     LIBSSH2_REALLOC_FUNC((*)), void *);
    using SessionHandshake = int(__cdecl *)(LIBSSH2_SESSION *, libssh2_socket_t);
    using SessionSetBlocking = void(__cdecl *)(LIBSSH2_SESSION *, int);
    using HostKeyHash = const char *(__cdecl *)(LIBSSH2_SESSION *, int);
    using AuthMemory = int(__cdecl *)(LIBSSH2_SESSION *, const char *, size_t, const char *, size_t, const char *,
                                      size_t, const char *);
    using SftpInit = LIBSSH2_SFTP *(__cdecl *)(LIBSSH2_SESSION *);
    using SftpShutdown = int(__cdecl *)(LIBSSH2_SFTP *);
    using SessionDisconnect = int(__cdecl *)(LIBSSH2_SESSION *, int, const char *, const char *);
    using SessionFree = int(__cdecl *)(LIBSSH2_SESSION *);

    Init initialize = Resolve<Init>(module, "libssh2_init");
    Exit shutdown = Resolve<Exit>(module, "libssh2_exit");
    SessionInit sessionInit = Resolve<SessionInit>(module, "libssh2_session_init_ex");
    SessionHandshake handshake = Resolve<SessionHandshake>(module, "libssh2_session_handshake");
    SessionSetBlocking setBlocking = Resolve<SessionSetBlocking>(module, "libssh2_session_set_blocking");
    HostKeyHash hostKeyHash = Resolve<HostKeyHash>(module, "libssh2_hostkey_hash");
    AuthMemory authenticate = Resolve<AuthMemory>(module, "libssh2_userauth_publickey_frommemory");
    SftpInit sftpInit = Resolve<SftpInit>(module, "libssh2_sftp_init");
    SftpShutdown sftpShutdown = Resolve<SftpShutdown>(module, "libssh2_sftp_shutdown");
    SessionDisconnect disconnect = Resolve<SessionDisconnect>(module, "libssh2_session_disconnect_ex");
    SessionFree sessionFree = Resolve<SessionFree>(module, "libssh2_session_free");
    if (!initialize || !shutdown || !sessionInit || !handshake || !setBlocking || !hostKeyHash || !authenticate ||
        !sftpInit || !sftpShutdown || !disconnect || !sessionFree)
    {
        FreeLibrary(module);
        return 8;
    }

    WSADATA winsock = {};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0)
    {
        FreeLibrary(module);
        return 9;
    }
    bool initialized = initialize(0) == 0;
    std::string host = ToAnsi(profile->hostName);
    char port[16] = {};
    sprintf_s(port, "%u", static_cast<unsigned>(profile->port));
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *addresses = nullptr;
    int networkResult = initialized && !host.empty() ? getaddrinfo(host.c_str(), port, &hints, &addresses) : -1;
    SocketGuard connection;
    if (networkResult == 0)
    {
        for (addrinfo *address = addresses; address; address = address->ai_next)
        {
            connection.socket = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
            if (connection.socket != INVALID_SOCKET &&
                connect(connection.socket, address->ai_addr, static_cast<int>(address->ai_addrlen)) == 0)
                break;
            if (connection.socket != INVALID_SOCKET)
                closesocket(connection.socket);
            connection.socket = INVALID_SOCKET;
        }
    }
    if (addresses)
        freeaddrinfo(addresses);

    LIBSSH2_SESSION *session = connection.socket != INVALID_SOCKET ? sessionInit(nullptr, nullptr, nullptr, nullptr)
                                                                   : nullptr;
    if (session)
        setBlocking(session, 1);
    bool handshakeOk = session && handshake(session, connection.socket) == 0;
    bool hostKeyAvailable = handshakeOk && hostKeyHash(session, LIBSSH2_HOSTKEY_HASH_SHA256) != nullptr;
    int authResult = hostKeyAvailable
                         ? authenticate(session, user, strlen(user), memoryKey.publicKeyFile.data(),
                                        memoryKey.publicKeyFile.size(),
                                        reinterpret_cast<const char *>(memoryKey.privateKeyPem.Data()),
                                        memoryKey.privateKeyPem.Size(), "")
                         : -1;
    LIBSSH2_SFTP *sftp = authResult == 0 ? sftpInit(session) : nullptr;
    bool success = sftp != nullptr;

    if (sftp)
        sftpShutdown(sftp);
    if (session)
    {
        disconnect(session, SSH_DISCONNECT_BY_APPLICATION, "Integration test complete", "");
        sessionFree(session);
    }
    if (initialized)
        shutdown();
    WSACleanup();
    FreeLibrary(module);

    printf("Direct integration: handshake=%s, host-key=%s, ppk-auth=%s, sftp=%s.\n", handshakeOk ? "yes" : "no",
           hostKeyAvailable ? "yes" : "no", authResult == 0 ? "yes" : "no", success ? "yes" : "no");
    return success ? 0 : 10;
}
