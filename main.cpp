#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>
#include <cstdlib>
using namespace std;

// Color definitions for console output
#define COLOR_RESET "\033[0m"
#define COLOR_CYAN "\033[36m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_BRIGHT "\033[1m"

const string BANNER = string(COLOR_CYAN) + R"(
      _ _ _    __ _           _           
  __| | | |  / _(_)_ __   __| | ___ _ __ 
 / _` | | | | |_| | '_ \ / _` |/ _ \ '__|
| (_| | | | |  _| | | | | (_| |  __/ |   
 \__,_|_|_| |_| |_|_| |_|\__,_|\___|_|   
)"
+ string(COLOR_BRIGHT) + "DLL Hijacking Scanner" + COLOR_RESET + "\n" +
COLOR_YELLOW + "by Tech and Fonfon" + COLOR_RESET + "\n";
vector<string> scan_dll_registry(bool verbose) {
    vector<string> results;
    const wstring reg_path = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\dll";

    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, reg_path.c_str(), 0, KEY_READ, &hKey);

    if (result != ERROR_SUCCESS) {
        if (verbose) {
            if (result == ERROR_FILE_NOT_FOUND) {
                cout << COLOR_YELLOW << "[!] Registry path not found: " << COLOR_RESET;
                wcout << reg_path << endl;
            }
            else {
                cout << COLOR_RED << "[!] Error accessing registry: " << result << COLOR_RESET << endl;
            }
        }
        return results;
    }

    DWORD index = 0;
    WCHAR name[256];
    DWORD nameSize = sizeof(name);
    DWORD type;
    BYTE data[4096];
    DWORD dataSize = sizeof(data);

    while (RegEnumValueW(hKey, index, name, &nameSize, NULL, &type, data, &dataSize) == ERROR_SUCCESS) {
        wstring valueName(name);

        if (valueName != L"MRUListEx" && type == REG_BINARY) {
            string textData;
            for (DWORD i = 0; i < dataSize; i++) {
                if (data[i] >= 32 && data[i] < 127) {
                    textData += static_cast<char>(data[i]);
                }
                else {
                    textData += ' ';
                }
            }

            // Convert to lowercase for case-insensitive search
            string lowerTextData = textData;
            for (char& c : lowerTextData) {
                c = tolower(c);
            }

            if (lowerTextData.find(".dll") != string::npos) {
                // Simple tokenization - this could be improved
                size_t pos = 0;
                while (pos < textData.length()) {
                    // Skip whitespace
                    while (pos < textData.length() && isspace(textData[pos])) pos++;
                    if (pos >= textData.length()) break;

                    size_t end = pos;
                    while (end < textData.length() && !isspace(textData[end])) end++;

                    string token = textData.substr(pos, end - pos);
                    string lowerToken = token;
                    for (char& c : lowerToken) {
                        c = tolower(c);
                    }

                    if (lowerToken.find(".dll") != string::npos) {
                        results.push_back(token);
                        if (verbose) {
                            cout << COLOR_GREEN << "[+] Found DLL reference: " << token << COLOR_RESET << endl;
                        }
                    }

                    pos = end;
                }
            }
        }

        index++;
        nameSize = sizeof(name);
        dataSize = sizeof(data);
    }

    RegCloseKey(hKey);
    return results;
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    string outputFile;

    // Simple argument parsing
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            }
            else {
                cerr << COLOR_RED << "[!] Output file not specified" << COLOR_RESET << endl;
                return 1;
            }
        }
    }

    cout << BANNER;

    vector<string> dll_entries = scan_dll_registry(verbose);

    if (!dll_entries.empty()) {
        cout << "\n" << COLOR_RED << "Possible DLL Hijacking Targets:" << COLOR_RESET << endl;
        for (size_t i = 0; i < dll_entries.size(); i++) {
            cout << "  " << i + 1 << ". " << COLOR_CYAN << dll_entries[i] << COLOR_RESET << endl;
        }

        if (!outputFile.empty()) {
            ofstream outFile(outputFile);
            if (outFile) {
                for (const auto& entry : dll_entries) {
                    outFile << entry << endl;
                }
                cout << "\n" << COLOR_GREEN << "[+] Results saved to " << outputFile << COLOR_RESET << endl;
            }
            else {
                cout << "\n" << COLOR_RED << "[!] Error saving results to file" << COLOR_RESET << endl;
            }
        }
    }
    else {
        cout << "\n" << COLOR_GREEN << "No suspicious DLL references found in registry." << COLOR_RESET << endl;
    }
    system("pause");
    return 0;
}