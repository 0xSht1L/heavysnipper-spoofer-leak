#include "spoofer.h"
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <thread>
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <wbemidl.h>
#include <tlhelp32.h>
#include <algorithm>
#include "utils.h"
#include "guard.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

class Spoofer {
private:
    float progress = 0.0f;
    float progressStep = 0.0f; // Для динамического расчёта прогресса
    vector<string> logMessages; // Для логирования

    void Log(const string& message, bool isError = false) {
        logMessages.push_back((isError ? "[ERROR] " : "[INFO] ") + message);
        SetConsoleColor(isError ? RED : WHITE);
        cout << (isError ? "[ERROR] " : "[INFO] ") << message << endl;
        SetConsoleColor(WHITE);
    }

    void SetProgressColor() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (progress <= 33.0f) {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY); // Красный
        }
        else if (progress <= 66.0f) {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // Желтый
        }
        else {
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY); // Зеленый
        }
    }

    void UpdateProgress() {
        SetProgressColor();
        cout << "\r";
        if (IsRussianLanguage()) {
            cout << "Прогресс: " << progress << "%" << flush;
        }
        else {
            cout << "Progress: " << progress << "%" << flush;
        }
    }

    string GenerateGUID() {
        GUID guid;
        if (FAILED(CoCreateGuid(&guid))) {
            Log("Не удалось сгенерировать GUID", true);
            return "";
        }
        char guidStr[40];
        sprintf_s(guidStr, "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return string(guidStr);
    }

    bool ExecuteCommand(const string& command) {
        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        PROCESS_INFORMATION pi = { 0 };
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = NULL;
        si.hStdOutput = NULL;
        si.hStdError = NULL;

        string cmd = "cmd.exe /C " + command;

        BOOL success = CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

        if (!success) {
            Log("Не удалось выполнить команду: " + command, true);
            return false;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (exitCode != 0) {
            Log("Команда завершилась с ошибкой: " + command, true);
            return false;
        }
        return true;
    }

    bool RegSetString(HKEY hRoot, const string& path, const string& name, const string& value) {
        HKEY hKey;
        if (RegOpenKeyExA(hRoot, path.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
            Log("Не удалось открыть ключ реестра: " + path, true);
            return false;
        }
        DWORD len = static_cast<DWORD>(value.length() + 1);
        bool success = RegSetValueExA(hKey, name.c_str(), 0, REG_SZ,
            reinterpret_cast<const BYTE*>(value.c_str()), len) == ERROR_SUCCESS;
        RegCloseKey(hKey);
        if (!success) {
            Log("Не удалось записать значение в реестр: " + path + "\\" + name, true);
        }
        return success;
    }

    bool RegDeleteKeyRecursive(HKEY hRoot, const string& path) {
        string rootStr;
        if (hRoot == HKEY_LOCAL_MACHINE) rootStr = "HKLM";
        else if (hRoot == HKEY_CURRENT_USER) rootStr = "HKCU";
        else if (hRoot == HKEY_CLASSES_ROOT) rootStr = "HKCR";
        else if (hRoot == HKEY_USERS) rootStr = "HKU";
        else {
            Log("Неподдерживаемый корневой ключ реестра", true);
            return false;
        }

        bool success = ExecuteCommand("reg delete \"" + rootStr + "\\" + path + "\" /f");
        if (!success) {
            Log("Не удалось удалить ключ реестра: " + path, true);
        }
        return success;
    }

    bool SpoofWMI(const string& className, const string& property, const string& newValue) {
        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            Log("Не удалось инициализировать COM", true);
            return false;
        }

        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            Log("Не удалось установить безопасность COM", true);
            CoUninitialize();
            return false;
        }

        IWbemLocator* pLoc = nullptr;
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            Log("Не удалось создать IWbemLocator", true);
            CoUninitialize();
            return false;
        }

        IWbemServices* pSvc = nullptr;
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        pLoc->Release();
        if (FAILED(hres)) {
            Log("Не удалось подключиться к WMI", true);
            CoUninitialize();
            return false;
        }

        IEnumWbemClassObject* pEnumerator = nullptr;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(("SELECT * FROM " + className).c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (FAILED(hres)) {
            Log("Не удалось выполнить запрос WMI для " + className, true);
            pSvc->Release();
            CoUninitialize();
            return false;
        }

        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;
        bool success = false;
        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (uReturn == 0) break;

            VARIANT vtProp;
            VariantInit(&vtProp);
            vtProp.vt = VT_BSTR;
            vtProp.bstrVal = _bstr_t(newValue.c_str());
            hres = pclsObj->Put(_bstr_t(property.c_str()), 0, &vtProp, 0);
            if (SUCCEEDED(hres)) {
                hres = pSvc->PutInstance(pclsObj, WBEM_FLAG_UPDATE_ONLY, NULL, NULL);
                success = SUCCEEDED(hres);
            }
            else {
                Log("Не удалось установить свойство " + property + " в " + className, true);
            }
            VariantClear(&vtProp);
            pclsObj->Release();
        }

        pEnumerator->Release();
        pSvc->Release();
        CoUninitialize();
        if (!success) {
            Log("Не удалось обновить WMI для " + className, true);
        }
        return success;
    }

    bool DeleteDirectory(const string& path) {
        SHFILEOPSTRUCTA fileOp = { 0 };
        fileOp.wFunc = FO_DELETE;
        string doubleNullTerminated = path + "\0";
        fileOp.pFrom = doubleNullTerminated.c_str();
        fileOp.fFlags = FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
        bool success = SHFileOperationA(&fileOp) == 0;
        if (!success) {
            Log("Не удалось удалить директорию: " + path, true);
        }
        return success;
    }

    string FindSteamDirectory() {
        WCHAR defaultPath[MAX_PATH];
        wcscpy_s(defaultPath, L"C:\\Program Files (x86)\\Steam");
        WCHAR steamExePath[MAX_PATH];
        swprintf_s(steamExePath, MAX_PATH, L"%s\\Steam.exe", defaultPath);
        if (GetFileAttributesW(steamExePath) != INVALID_FILE_ATTRIBUTES) {
            return WCHARToString(defaultPath);
        }
        Log("Steam не найден в стандартной директории", true);
        return "";
    }

    vector<string> GetSteamLibraryFolders(const string& steamPath) {
        vector<string> libraryFolders;
        libraryFolders.push_back(steamPath + "\\steamapps");
        string libraryFoldersFile = steamPath + "\\steamapps\\libraryfolders.vdf";

        HANDLE hFile = CreateFileA(libraryFoldersFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            Log("Не удалось открыть libraryfolders.vdf", true);
            return libraryFolders;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            Log("Не удалось определить размер libraryfolders.vdf", true);
            CloseHandle(hFile);
            return libraryFolders;
        }

        vector<char> buffer(fileSize + 1);
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
            Log("Не удалось прочитать libraryfolders.vdf", true);
            CloseHandle(hFile);
            return libraryFolders;
        }
        buffer[bytesRead] = '\0';
        CloseHandle(hFile);

        string content(buffer.data());
        size_t pos = 0;
        while ((pos = content.find("\"path\"")) != string::npos) {
            size_t quote1 = content.find("\"", pos + 6);
            size_t quote2 = content.find("\"", quote1 + 1);
            if (quote1 != string::npos && quote2 != string::npos) {
                string libraryPath = content.substr(quote1 + 1, quote2 - quote1 - 1);
                replace(libraryPath.begin(), libraryPath.end(), '/', '\\');
                libraryFolders.push_back(libraryPath + "\\steamapps");
                pos = quote2 + 1;
            }
            else {
                break;
            }
        }
        return libraryFolders;
    }

    vector<string> FindRustDirectories(const string& steamPath) {
        vector<string> rustDirs;
        vector<string> libraryFolders = GetSteamLibraryFolders(steamPath);
        for (const string& library : libraryFolders) {
            string rustPath = library + "\\common\\Rust";
            if (GetFileAttributesA(rustPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                rustDirs.push_back(rustPath);
            }
        }
        return rustDirs;
    }

    bool CloseSteamProcess() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            Log("Не удалось создать снимок процессов", true);
            return false;
        }

        PROCESSENTRY32 pe32 = { sizeof(pe32) };
        bool success = false;
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, L"Steam.exe") == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        success = TerminateProcess(hProcess, 0) != 0;
                        if (!success) {
                            Log("Не удалось завершить процесс Steam.exe", true);
                        }
                        CloseHandle(hProcess);
                    }
                    else {
                        Log("Не удалось открыть процесс Steam.exe", true);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        return success;
    }

    void DeleteSteamFiles(const string& steamPath, const vector<string>& rustDirs) {
        vector<string> steamPathsToDelete = {
            steamPath + "\\userdata",
            steamPath + "\\config",
            steamPath + "\\logs",
            steamPath + "\\dumps",
            steamPath + "\\depotcache"
        };

        for (const string& path : steamPathsToDelete) {
            if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                DeleteDirectory(path);
            }
        }

        for (const string& rustPath : rustDirs) {
            vector<string> rustPathsToDelete = {
                rustPath + "\\cfg",
                rustPath + "\\logs",
                rustPath + "\\dumps"
            };
            for (const string& path : rustPathsToDelete) {
                if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    DeleteDirectory(path);
                }
            }
        }
    }

    void ClearSteamRegistry() {
        vector<pair<HKEY, string>> steamRegKeys = {
            {HKEY_CURRENT_USER, "Software\\Valve\\Steam"},
            {HKEY_LOCAL_MACHINE, "Software\\Valve\\Steam"},
            {HKEY_CURRENT_USER, "Software\\Valve\\SteamApps"},
            {HKEY_LOCAL_MACHINE, "Software\\Valve\\SteamApps"}
        };
        for (const auto& pair : steamRegKeys) {
            HKEY hRoot = pair.first;
            const string& key = pair.second;
            RegDeleteKeyRecursive(hRoot, key);
        }
        ExecuteCommand("reg add \"HKCU\\Software\\Valve\\Steam\" /f");
    }

    void ClearSteam() {
        string steamPath = FindSteamDirectory();
        if (steamPath.empty()) {
            Log("Steam не найден, пропускаем очистку", true);
            return;
        }
        vector<string> rustDirs = FindRustDirectories(steamPath);
        CloseSteamProcess();
        DeleteSteamFiles(steamPath, rustDirs);
        ClearSteamRegistry();
        progress += progressStep;
        UpdateProgress();
        Log("Очистка Steam завершена");
    }

    void ClearEAC() {
        vector<string> eacPaths = {
            "C:\\ProgramData\\EasyAntiCheat",
            "C:\\Program Files (x86)\\EasyAntiCheat",
            "C:\\Program Files (x86)\\EasyAntiCheat_EOS",
            "C:\\Windows\\System32\\EasyAntiCheat.sys",
            "C:\\Windows\\System32\\EasyAntiCheat_EOS.sys",
            "C:\\Windows\\SysWOW64\\EasyAntiCheat.sys",
            "C:\\Windows\\SysWOW64\\EasyAntiCheat_EOS.sys"
        };
        for (const string& path : eacPaths) {
            if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                DeleteDirectory(path);
            }
        }

        vector<pair<HKEY, string>> eacRegKeys = {
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat_EOS"},
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\EasyAntiCheat"},
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\EasyAntiCheat_EOS"}
        };
        for (const auto& pair : eacRegKeys) {
            HKEY hRoot = pair.first;
            const string& key = pair.second;
            RegDeleteKeyRecursive(hRoot, key);
        }

        ExecuteCommand("sc stop EasyAntiCheat");
        ExecuteCommand("sc stop EasyAntiCheat_EOS");
        progress += progressStep;
        UpdateProgress();
        Log("Очистка EAC завершена");
    }

    void ClearBattlEye() {
        vector<string> bePaths = {
            "C:\\Program Files (x86)\\Common Files\\BattlEye",
            "C:\\ProgramData\\BattlEye",
            "C:\\Windows\\System32\\BEService.exe",
            "C:\\Windows\\SysWOW64\\BEService.exe"
        };
        for (const string& path : bePaths) {
            if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                DeleteDirectory(path);
            }
        }

        vector<pair<HKEY, string>> beRegKeys = {
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\BEService"},
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\BattlEye"}
        };
        for (const auto& pair : beRegKeys) {
            HKEY hRoot = pair.first;
            const string& key = pair.second;
            RegDeleteKeyRecursive(hRoot, key);
        }

        ExecuteCommand("sc stop BEService");
        progress += progressStep;
        UpdateProgress();
        Log("Очистка BattlEye завершена");
    }

    void SpoofGUID() {
        string newGuid = GenerateGUID();
        if (newGuid.empty()) return;
        if (RegSetString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", newGuid)) {
            SpoofWMI("Win32_ComputerSystemProduct", "UUID", newGuid);
        }
        progress += progressStep;
        UpdateProgress();
        Log("Спуфинг GUID завершен");
    }

    void SpoofProductID() {
        string newId = GenerateRandomString(5) + "-" + GenerateRandomString(5) + "-" +
            GenerateRandomString(5) + "-" + GenerateRandomString(5);
        if (RegSetString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId", newId)) {
            Log("Спуфинг ProductID завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofVolumeSerial() {
        string newVolumeSerial = GenerateRandomString(8);
        if (SpoofWMI("Win32_Volume", "SerialNumber", newVolumeSerial)) {
            Log("Спуфинг VolumeSerial завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofDiskSerial() {
        HANDLE hDevice = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDevice != INVALID_HANDLE_VALUE) {
            string newSerial = GenerateRandomString(8);
            if (RegSetString(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi", "SerialNumber", newSerial)) {
                SpoofWMI("Win32_DiskDrive", "SerialNumber", newSerial);
                Log("Спуфинг DiskSerial завершен");
            }
            CloseHandle(hDevice);
        }
        else {
            Log("Не удалось открыть PhysicalDrive0", true);
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofMAC() {
        ULONG bufferSize = 0;
        GetAdaptersInfo(NULL, &bufferSize);
        PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(bufferSize);
        if (pAdapterInfo == nullptr) {
            Log("Не удалось выделить память для адаптеров", true);
            return;
        }

        if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == NO_ERROR) {
            string newMAC = "";
            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<> dis(0, 15);
            for (int i = 0; i < 12; i++) {
                int val = dis(gen);
                newMAC += (val < 10 ? char('0' + val) : char('A' + (val - 10)));
                if (i % 2 == 1 && i != 11) newMAC += ":";
            }

            string adapterName = pAdapterInfo->AdapterName;
            if (RegSetString(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\0000",
                "NetworkAddress", newMAC)) {
                SpoofWMI("Win32_NetworkAdapter", "MACAddress", newMAC);
                string disableCmd = "netsh interface set interface name=\"" + adapterName + "\" admin=disable";
                string enableCmd = "netsh interface set interface name=\"" + adapterName + "\" admin=enable";
                ExecuteCommand(disableCmd);
                this_thread::sleep_for(chrono::seconds(1));
                ExecuteCommand(enableCmd);
                Log("Спуфинг MAC-адреса завершен");
            }
        }
        else {
            Log("Не удалось получить информацию об адаптерах", true);
        }
        free(pAdapterInfo);
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofCPUSerial() {
        string newSerial = "CPU-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "ProcessorId", newSerial)) {
            SpoofWMI("Win32_Processor", "ProcessorId", newSerial);
            Log("Спуфинг CPU Serial завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofGPUSerial() {
        string newSerial = "GPU-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\PCI",
            "DeviceID", newSerial)) {
            SpoofWMI("Win32_VideoController", "PNPDeviceID", newSerial);
            Log("Спуфинг GPU Serial завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofChassisSerial() {
        string newSerial = "CHASSIS-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System",
            "SystemSerialNumber", newSerial)) {
            SpoofWMI("Win32_SystemEnclosure", "SerialNumber", newSerial);
            Log("Спуфинг Chassis Serial завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofRAMSerial() {
        string newSerial = "RAM-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\Memory",
            "SerialNumber", newSerial)) {
            SpoofWMI("Win32_PhysicalMemory", "SerialNumber", newSerial);
            Log("Спуфинг RAM Serial завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofSSDHDSerial() {
        string newSerial = "DISK-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi",
            "SerialNumber", newSerial)) {
            SpoofWMI("Win32_DiskDrive", "SerialNumber", newSerial);
            Log("Спуфинг SSD/HD Serial завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofMotherboard() {
        string newSerial = "MB-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "BaseBoardSerial", newSerial)) {
            SpoofWMI("Win32_BaseBoard", "SerialNumber", newSerial);
            Log("Спуфинг Motherboard Serial завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofBIOS() {
        string newSerial = "BIOS-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "BIOSSerial", newSerial)) {
            SpoofWMI("Win32_BIOS", "SerialNumber", newSerial);
            Log("Спуфинг BIOS Serial завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofEDID() {
        string newSerial = "MON-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
            "Device Parameters", newSerial)) {
            SpoofWMI("Win32_DesktopMonitor", "PNPDeviceID", newSerial);
            Log("Спуфинг EDID завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofSMBIOS() {
        string newSerial = "SMBIOS-" + GenerateRandomString(12);
        if (RegSetString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System",
            "SystemBiosVersion", newSerial)) {
            SpoofWMI("Win32_BIOS", "SMBIOSBIOSVersion", newSerial);
            Log("Спуфинг SMBIOS завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofUUID() {
        string newUUID = GenerateGUID();
        if (newUUID.empty()) return;
        if (RegSetString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "SystemUUID", newUUID)) {
            SpoofWMI("Win32_ComputerSystemProduct", "UUID", newUUID);
            Log("Спуфинг UUID завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofUSBDevices() {
        string newSerial = "USB-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USB",
            "SerialNumber", newSerial)) {
            SpoofWMI("Win32_USBControllerDevice", "Dependent", newSerial);
            Log("Спуфинг USB Devices завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofNetworkAdapters() {
        string newID = "NET-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
            "AdapterID", newID)) {
            SpoofWMI("Win32_NetworkAdapter", "DeviceID", newID);
            Log("Спуфинг Network Adapters завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void SpoofAudioSerial() {
        string newSerial = "AUDIO-" + GenerateRandomString(10);
        if (RegSetString(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\HDAUDIO",
            "DeviceID", newSerial)) {
            SpoofWMI("Win32_SoundDevice", "DeviceID", newSerial);
            Log("Спуфинг Audio Serial завершен");
        }
        progress += progressStep;
        UpdateProgress();
    }

    void KillProcesses() {
        vector<string> processes = {
            "smartscreen.exe", "EasyAntiCheat.exe", "dnf.exe", "DNF.exe", "CrossProxy.exe",
            "tensafe_1.exe", "TenSafe_1.exe", "tensafe_2.exe", "tencentdl.exe", "TenioDL.exe",
            "uishell.exe", "BackgroundDownloader.exe", "conime.exe", "QQDL.EXE", "qqlogin.exe",
            "dnfchina.exe", "dnfchinatest.exe", "txplatform.exe", "TXPlatform.exe",
            "OriginWebHelperService.exe", "Origin.exe", "OriginClientService.exe",
            "OriginER.exe", "OriginThinSetupInternal.exe", "OriginLegacyCLI.exe",
            "Agent.exe", "Client.exe"
        };
        for (const auto& process : processes) {
            if (ExecuteCommand("taskkill /f /im " + process)) {
                Log("Процесс " + process + " завершен");
            }
        }
        progress += progressStep;
        UpdateProgress();
    }

    string ExpandUsername(const string& path) {
        char username[UNLEN + 1];
        DWORD username_len = UNLEN + 1;
        GetUserNameA(username, &username_len);
        string result = path;
        size_t pos = result.find("%username%");
        while (pos != string::npos) {
            result.replace(pos, 10, username);
            pos = result.find("%username%", pos + strlen(username));
        }
        return result;
    }

    void CleanFiles() {
        vector<string> filesToDelete = {
            "C:\\Windows\\SysWOW64\\config\\systemprofile\\AppData\\Roaming\\Origin\\Telemetry\\*",
            "C:\\Windows\\SysWOW64\\config\\systemprofile\\AppData\\Roaming\\Origin\\*.*",
            "C:\\ProgramData\\Electronic Arts\\EA Services\\License\\*.*",
            "C:\\Program Files (x86)\\EasyAntiCheat\\EasyAntiCheat.sys",
            "C:\\Program Files (x86)\\Origin\\*.log",
            "C:\\Windows\\System32\\eac_usermode_*.dll",
            "C:\\Users\\%username%\\AppData\\LocalLow\\DNF\\*.tr",
            "C:\\Users\\%username%\\AppData\\Local\\Origin\\*.log",
            "C:\\Users\\%username%\\AppData\\Roaming\\Origin\\Telemetry\\*",
            "C:\\Windows\\Temp\\*.tmp",
            "C:\\Windows\\Prefetch\\*.*"
        };

        for (string& path : filesToDelete) {
            if (path.find("%username%") != string::npos) {
                path = ExpandUsername(path);
            }
            if (path.find("*") != string::npos) {
                WIN32_FIND_DATAA findData;
                HANDLE hFind = FindFirstFileA(path.c_str(), &findData);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                            string filePath = path.substr(0, path.find_last_of("\\")) + "\\" + findData.cFileName;
                            if (DeleteFileA(filePath.c_str())) {
                                Log("Удалён файл: " + filePath);
                            }
                        }
                    } while (FindNextFileA(hFind, &findData));
                    FindClose(hFind);
                }
            }
            else {
                if (DeleteFileA(path.c_str())) {
                    Log("Удалён файл: " + path);
                }
            }
        }
        progress += progressStep;
        UpdateProgress();
        Log("Очистка файлов завершена");
    }

    bool IsAdmin() {
        BOOL isAdmin = FALSE;
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD dwSize;
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                isAdmin = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }
        return isAdmin != FALSE;
    }

public:
    void LiteSpoof() {
        if (!IsAdmin()) {
            SetConsoleColor(RED);
            if (IsRussianLanguage()) {
                cout << "Ошибка: Запустите программу от имени администратора!\n";
            }
            else {
                cout << "Error: Please run the program as an administrator!\n";
            }
            SetConsoleColor(WHITE);
            return;
        }

        isSpoofing = true; // Устанавливаем флаг перед началом спуфа
        progress = 0.0f;
        int totalSteps = 6; // Количество методов в LiteSpoof
        progressStep = 100.0f / totalSteps;

        SetConsoleColor(YELLOW);
        if (IsRussianLanguage()) {
            cout << "Запуск Lite Spoof...\n";
        }
        else {
            cout << "Starting Lite Spoof...\n";
        }

        SpoofGUID();
        SpoofMAC();
        SpoofProductID();
        KillProcesses();
        ClearSteam();
        ClearBattlEye(); // Добавляем очистку BattlEye
        CleanFiles();

        progress = 100.0f;
        UpdateProgress();
        SetConsoleColor(GREEN);
        cout << "\n";
        if (IsRussianLanguage()) {
            cout << "Lite Spoof завершен!\n";
        }
        else {
            cout << "Lite Spoof completed!\n";
        }
        SetConsoleColor(WHITE);
        isSpoofing = false; // Сбрасываем флаг после завершения спуфа
    }

    void FullSpoof() {
        if (!IsAdmin()) {
            SetConsoleColor(RED);
            if (IsRussianLanguage()) {
                cout << "Ошибка: Запустите программу от имени администратора!\n";
            }
            else {
                cout << "Error: Please run the program as an administrator!\n";
            }
            SetConsoleColor(WHITE);
            return;
        }

        isSpoofing = true; // Устанавливаем флаг перед началом спуфа
        progress = 0.0f;
        int totalSteps = 21; // Количество методов в FullSpoof
        progressStep = 100.0f / totalSteps;

        SetConsoleColor(YELLOW);
        if (IsRussianLanguage()) {
            cout << "Запуск Full Spoof...\n";
        }
        else {
            cout << "Starting Full Spoof...\n";
        }

        SpoofGUID();
        SpoofMAC();
        SpoofProductID();
        SpoofVolumeSerial();
        SpoofDiskSerial();
        SpoofCPUSerial();
        SpoofGPUSerial();
        SpoofChassisSerial();
        SpoofRAMSerial();
        SpoofSSDHDSerial();
        SpoofMotherboard();
        SpoofBIOS();
        SpoofEDID();
        SpoofSMBIOS();
        SpoofUUID();
        SpoofUSBDevices();
        SpoofNetworkAdapters();
        SpoofAudioSerial();
        KillProcesses();
        ClearSteam();
        ClearEAC();
        ClearBattlEye(); // Добавляем очистку BattlEye
        CleanFiles();

        progress = 100.0f;
        UpdateProgress();
        SetConsoleColor(GREEN);
        cout << "\n";
        if (IsRussianLanguage()) {
            cout << "Full Spoof завершен!\n";
        }
        else {
            cout << "Full Spoof completed!\n";
        }
        SetConsoleColor(WHITE);
        isSpoofing = false; // Сбрасываем флаг после завершения спуфа
    }
};

void LiteSpoof() {
    Spoofer spoofer;
    spoofer.LiteSpoof();
}

void FullSpoof() {
    Spoofer spoofer;
    spoofer.FullSpoof();
}