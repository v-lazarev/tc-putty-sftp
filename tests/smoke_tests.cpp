#include "../ppk_v3_rsa.h"
#include "../putty_session_provider.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int main(int argc, char **argv)
{
    if (tcputty::DecodeSessionName(L"prod%20blue+green") != L"prod blue+green")
    {
        fprintf(stderr, "PuTTY session name decoding failed.\n");
        return 1;
    }

    std::vector<tcputty::SessionProfile> sessions;
    std::wstring registryError;
    if (!tcputty::EnumerateSessions(sessions, &registryError))
    {
        fprintf(stderr, "PuTTY registry enumeration failed.\n");
        return 2;
    }

    char temporaryDirectory[MAX_PATH] = {};
    char temporaryIni[MAX_PATH] = {};
    if (!GetTempPathA(MAX_PATH, temporaryDirectory) || !GetTempFileNameA(temporaryDirectory, "tps", 0, temporaryIni))
    {
        fprintf(stderr, "Unable to create a temporary test INI.\n");
        return 3;
    }
    WritePrivateProfileStringA("existing", "server", "example.invalid", temporaryIni);
    std::string syncError;
    int synchronized = tcputty::SyncSessionsToIni(temporaryIni, &syncError);
    int resynchronized = tcputty::SyncSessionsToIni(temporaryIni, &syncError);
    bool syncOk = synchronized >= 0 && resynchronized >= 0 &&
                  static_cast<size_t>(synchronized) == sessions.size() &&
                  static_cast<size_t>(resynchronized) == sessions.size();
    char existingServer[64] = {};
    GetPrivateProfileStringA("existing", "server", "", existingServer, sizeof(existingServer), temporaryIni);
    syncOk = syncOk && strcmp(existingServer, "example.invalid") == 0;
    DeleteFileA(temporaryIni);
    if (!syncOk)
    {
        fprintf(stderr,
                "PuTTY session INI synchronization failed "
                "(enumerated=%zu, synchronized=%d/%d, preserved=%d).\n",
                sessions.size(), synchronized, resynchronized,
                strcmp(existingServer, "example.invalid") == 0 ? 1 : 0);
        return 4;
    }

    if (argc > 1)
    {
        tcputty::MemoryKey key;
        std::string error;
        if (tcputty::LoadPpkV3Key(argv[1], key, error) != tcputty::PpkLoadResult::Success)
        {
            fprintf(stderr, "PPK v3 in-memory conversion failed: %s\n", error.c_str());
            return 5;
        }
        static const char pemHeader[] = "-----BEGIN RSA PRIVATE KEY-----\n";
        bool validRepresentation = false;
        if (key.algorithm == tcputty::MemoryKey::Algorithm::Rsa)
            validRepresentation = key.privateKeyPem.Size() > sizeof(pemHeader) &&
                                  memcmp(key.privateKeyPem.Data(), pemHeader, sizeof(pemHeader) - 1) == 0 &&
                                  key.publicKeyFile.compare(0, 8, "ssh-rsa ") == 0;
        else if (key.algorithm == tcputty::MemoryKey::Algorithm::Ed25519)
            validRepresentation = key.privateKeySeed.Size() == 32 && key.publicKeyPoint.Size() == 32 &&
                                  key.publicKeyBlob.Size() == 51 &&
                                  key.publicKeyFile.compare(0, 12, "ssh-ed25519 ") == 0;
        if (!validRepresentation)
        {
            fprintf(stderr, "PPK conversion returned an invalid in-memory representation.\n");
            return 6;
        }
    }

    printf("Smoke tests passed: %zu live PuTTY session(s).\n", sessions.size());
    return 0;
}
