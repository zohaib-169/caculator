/*
    File Encryptor / Decryptor  (v9)
    ------------------------------------------------------------
    New in this version:
    - BUGFIX: wrong-key retries now happen right there in place
      instead of kicking you back to the main menu
    - BUGFIX: sort-order prompt is no longer asked on every single
      file listing -- it's now a persistent setting (Settings menu)
    - Settings menu (default sort order, master password toggle) --
      saved to disk so it's remembered next run, and built so future
      settings can be added easily
    - Key generator: auto-generates a strong random key, shown once
    - Recent files list (last 5 encrypt/decrypt actions)
    - Search-while-browsing: type /text to filter the current folder
    - Batch mode: encrypt or decrypt every file in a folder at once
    - Key file support: use any file as your key instead of typing one
    - CLI arguments: ./encryptor encrypt <file> <key>  (skips the menu)
    - Optional master password lock on the whole app
    - File integrity checksum (FNV-1a) -- warns if a decrypted file
      was corrupted/tampered with, separate from a wrong-key check
    - Stats dashboard pulled from the activity log

    Author: Muhammad Ali
    Version: 9.0
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <functional>
#include <algorithm>
#include <string>
#include <filesystem>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <cctype>
#include <random>
#include <vector>
#include <map>
#include <iomanip>
#include <dlfcn.h>

using namespace std;
namespace fs = std::filesystem;

// ---------- Colors ----------
namespace col {
    const string RESET  = "\033[0m";
    const string GREEN  = "\033[1;32m";
    const string RED    = "\033[1;31m";
    const string CYAN   = "\033[1;36m";
    const string YELLOW = "\033[1;33m";
    const string BOLD   = "\033[1m";
    const string MAGENTA= "\033[1;35m";
}

// ---------- Paths ----------
string getStorageRoot() {
    const char* home = getenv("HOME");
    string homeDir = home ? string(home) : ".";
    return homeDir + "/storage/shared/";
}
const string STORAGE_ROOT = getStorageRoot();
const string WORK_DIR = STORAGE_ROOT + "FileEncryptor/";
const string LOG_FILE = WORK_DIR + "activity_log.txt";
const string PLUGIN_DIR = WORK_DIR + "plugins/";
const string META_DIR = WORK_DIR + "meta/";
const string ATTEMPTS_DIR = WORK_DIR + "attempts/";
const string RECENT_FILE = WORK_DIR + "recent_files.txt";
const string SETTINGS_FILE = WORK_DIR + "settings.txt";

const string MAGIC_SIGNATURE = "FEP1";
const int MAX_ATTEMPTS = 5;
const uint32_t FNV_OFFSET = 2166136261u;
const uint32_t FNV_PRIME  = 16777619u;

// ---------- Settings ----------
struct Settings {
    int sortOrder = 1;                 // 1 = name, 2 = date modified, 3 = size
    bool masterPasswordEnabled = false;
    string masterPasswordHash = "";
};
Settings g_settings;

string hashPath(const string& path) {
    size_t h = std::hash<string>{}(path);
    ostringstream oss;
    oss << hex << h;
    return oss.str();
}

// Same trick used for per-file attempt IDs -- good enough for a
// "don't type it in plaintext next to the flag" master password check.
// NOTE: like the rest of this project, this is for learning purposes,
// not a cryptographically secure password store.
string simpleHash(const string& text) {
    return hashPath(text);
}

void loadSettings() {
    ifstream f(SETTINGS_FILE);
    if (!f) return;
    string line;
    while (getline(f, line)) {
        size_t eq = line.find('=');
        if (eq == string::npos) continue;
        string key = line.substr(0, eq);
        string val = line.substr(eq + 1);
        if (key == "sortOrder") g_settings.sortOrder = val.empty() ? 1 : stoi(val);
        else if (key == "masterPasswordEnabled") g_settings.masterPasswordEnabled = (val == "1");
        else if (key == "masterPasswordHash") g_settings.masterPasswordHash = val;
    }
}

void saveSettings() {
    ofstream f(SETTINGS_FILE);
    if (!f) return;
    f << "sortOrder=" << g_settings.sortOrder << "\n";
    f << "masterPasswordEnabled=" << (g_settings.masterPasswordEnabled ? "1" : "0") << "\n";
    f << "masterPasswordHash=" << g_settings.masterPasswordHash << "\n";
}

int getFailedAttempts(const string& fileId) {
    ifstream f(ATTEMPTS_DIR + fileId + ".txt");
    if (!f) return 0;
    int count = 0;
    f >> count;
    return count;
}
void setFailedAttempts(const string& fileId, int count) {
    ofstream f(ATTEMPTS_DIR + fileId + ".txt");
    f << count;
}
void resetFailedAttempts(const string& fileId) {
    fs::remove(ATTEMPTS_DIR + fileId + ".txt");
}

void ensureWorkDirExists() {
    if (!fs::exists(WORK_DIR)) {
        fs::create_directories(WORK_DIR);
        cout << col::CYAN << "Created folder: " << WORK_DIR << col::RESET << "\n";
    }
    if (!fs::exists(PLUGIN_DIR)) fs::create_directories(PLUGIN_DIR);
    if (!fs::exists(META_DIR)) fs::create_directories(META_DIR);
    if (!fs::exists(ATTEMPTS_DIR)) fs::create_directories(ATTEMPTS_DIR);
}

string detectCompiler() {
    if (std::system("clang++ --version > /dev/null 2>&1") == 0) return "clang++";
    if (std::system("g++ --version > /dev/null 2>&1") == 0) return "g++";
    return "";
}

string toLowerStr(const string& s) {
    string out = s;
    transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return tolower(c); });
    return out;
}

string humanReadableSize(uintmax_t bytes) {
    ostringstream oss;
    if (bytes < 1024) oss << bytes << " B";
    else if (bytes < 1024*1024) oss << fixed << setprecision(1) << bytes/1024.0 << " KB";
    else oss << fixed << setprecision(2) << bytes/(1024.0*1024.0) << " MB";
    return oss.str();
}

int readMenuChoice() {
    int choice;
    while (!(cin >> choice)) {
        cout << col::RED << "Please enter a number: " << col::RESET;
        cin.clear();
        cin.ignore(10000, '\n');
    }
    return choice;
}

// ---------- File browser (v9: search filter + optional folder-pick mode) ----------
string browseAndPickFile(string startDir, bool pickFolder = false) {
    string currentDir = startDir;
    string filterQuery = "";

    while (true) {
        vector<fs::path> dirs;
        vector<fs::path> files;

        for (const auto& entry : fs::directory_iterator(currentDir)) {
            string name = entry.path().filename().string();
            if (name == "FileEncryptor") continue;
            if (!filterQuery.empty() && toLowerStr(name).find(toLowerStr(filterQuery)) == string::npos) continue;
            if (entry.is_directory()) dirs.push_back(entry.path());
            else if (entry.is_regular_file()) files.push_back(entry.path());
        }

        sort(dirs.begin(), dirs.end());
        if (g_settings.sortOrder == 1) {
            sort(files.begin(), files.end());
        } else if (g_settings.sortOrder == 2) {
            sort(files.begin(), files.end(), [](const fs::path& a, const fs::path& b) {
                return fs::last_write_time(a) > fs::last_write_time(b);
            });
        } else if (g_settings.sortOrder == 3) {
            sort(files.begin(), files.end(), [](const fs::path& a, const fs::path& b) {
                return fs::file_size(a) > fs::file_size(b);
            });
        }

        cout << col::CYAN << "\nCurrent folder: " << currentDir << col::RESET;
        if (!filterQuery.empty()) cout << col::YELLOW << "  (filtered: \"" << filterQuery << "\")" << col::RESET;
        cout << "\n";

        int index = 1;
        vector<fs::path> combined;

        if (currentDir != STORAGE_ROOT) {
            cout << "  " << col::BOLD << "0" << col::RESET << ". .. (go up one folder)\n";
        }
        for (auto& d : dirs) {
            cout << "  " << col::BOLD << index << col::RESET << ". [DIR] " << d.filename().string() << "\n";
            combined.push_back(d);
            index++;
        }
        for (auto& f : files) {
            uintmax_t sz = fs::file_size(f);
            cout << "  " << col::BOLD << index << col::RESET << ". " << f.filename().string()
                 << "  (" << humanReadableSize(sz) << ")\n";
            combined.push_back(f);
            index++;
        }
        if (dirs.empty() && files.empty()) {
            cout << col::YELLOW << "  (nothing here)\n" << col::RESET;
        }
        if (pickFolder) {
            cout << "  " << col::BOLD << "s" << col::RESET << ". [SELECT THIS FOLDER for batch mode]\n";
        }

        cout << "\nEnter a number, 0 to go up, /text to search, /clear to clear search"
             << (pickFolder ? ", 's' to select this folder" : "") << ", or 'q' to cancel: ";
        string input;
        cin >> input;

        if (input == "q" || input == "Q") return "";
        if (pickFolder && (input == "s" || input == "S")) return currentDir;

        if (!input.empty() && input[0] == '/') {
            string arg = input.substr(1);
            filterQuery = (arg == "clear") ? "" : arg;
            continue;
        }

        if (input == "0" && currentDir != STORAGE_ROOT) {
            currentDir = fs::path(currentDir).parent_path().string();
            filterQuery = "";
            continue;
        }

        bool isNumber = !input.empty() && input.find_first_not_of("0123456789") == string::npos;
        if (!isNumber) {
            cout << col::RED << "Invalid input.\n" << col::RESET;
            continue;
        }
        int choice = stoi(input);
        if (choice < 1 || choice > (int)combined.size()) {
            cout << col::RED << "Invalid choice.\n" << col::RESET;
            continue;
        }

        fs::path picked = combined[choice - 1];
        if (fs::is_directory(picked)) {
            currentDir = picked.string();
            filterQuery = "";
            continue;
        } else {
            if (pickFolder) {
                cout << col::YELLOW << "You're in folder-select mode -- press 's' to use the CURRENT "
                     << "folder, or navigate into a different one.\n" << col::RESET;
                continue;
            }
            return picked.string();
        }
    }
}

void saveOriginalLocation(const string& encFileName, const string& originalFullPath) {
    ofstream meta(META_DIR + encFileName + ".meta");
    meta << originalFullPath;
}
string loadOriginalLocation(const string& encFileName) {
    ifstream meta(META_DIR + encFileName + ".meta");
    if (!meta) return "";
    string path;
    getline(meta, path);
    return path;
}

// ---------- Logging ----------
string timestampNow() {
    time_t now = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buf);
}

void logActivity(const string& action, const string& filename, bool success, long long sizeBytes = -1) {
    ofstream log(LOG_FILE, ios::app);
    if (!log) return;
    log << "[" << timestampNow() << "] " << action << " - " << filename
        << " - " << (success ? "SUCCESS" : "FAILED");
    if (sizeBytes >= 0) log << " | SIZE:" << sizeBytes;
    log << "\n";
}

// ---------- Recent files ----------
vector<string> readRecentFiles() {
    vector<string> lines;
    ifstream f(RECENT_FILE);
    string line;
    while (getline(f, line)) if (!line.empty()) lines.push_back(line);
    return lines;
}

void addRecentFile(const string& action, const string& filename) {
    vector<string> lines = readRecentFiles();
    string entry = timestampNow() + "|" + action + "|" + filename;
    lines.insert(lines.begin(), entry);
    if (lines.size() > 5) lines.resize(5);
    ofstream f(RECENT_FILE, ios::trunc);
    for (auto& l : lines) f << l << "\n";
}

void showRecentFilesFlow() {
    vector<string> lines = readRecentFiles();
    cout << col::CYAN << "\n----- RECENT FILES (last " << lines.size() << ") -----\n" << col::RESET;
    if (lines.empty()) {
        cout << col::YELLOW << "  (nothing yet -- encrypt or decrypt a file first)\n" << col::RESET;
        return;
    }
    int i = 1;
    for (auto& l : lines) {
        stringstream ss(l);
        string ts, action, filename;
        getline(ss, ts, '|');
        getline(ss, action, '|');
        getline(ss, filename, '|');
        cout << "  " << col::BOLD << i << col::RESET << ". [" << action << "] " << filename
             << "  (" << ts << ")\n";
        i++;
    }
}

// ---------- Developer info / random tips ----------
void showDeveloperInfo() {
    cout << col::MAGENTA << "\n===== ABOUT THIS PROJECT =====\n" << col::RESET;
    cout << "File Encryptor / Decryptor v9.0\n";
    cout << "Developed by: Muhammad Ali\n";
    cout << "Software Engineering Undergraduate, University of Gujrat\n";
    cout << "An applied C++ project exploring binary file I/O, the C++17\n";
    cout << "filesystem library, and the foundational principles of\n";
    cout << "symmetric encryption.\n";

    cout << col::MAGENTA << "\n----- VERSION HISTORY -----\n" << col::RESET;
    cout << col::BOLD << "v1.0" << col::RESET << " - Core XOR encryption/decryption engine.\n";
    cout << col::BOLD << "v2.0" << col::RESET << " - Automated folder management.\n";
    cout << col::BOLD << "v3.0" << col::RESET << " - Interface improvements: colored output, progress\n"
         << "       indicator, key confirmation, activity logging.\n";
    cout << col::BOLD << "v4.0" << col::RESET << " - Plugin architecture for loading compiled updates.\n";
    cout << col::BOLD << "v5.0" << col::RESET << " - In-application compilation of update code.\n";
    cout << col::BOLD << "v6.0" << col::RESET << " - Full storage browsing with automatic restore to\n"
         << "       original file location.\n";
    cout << col::BOLD << "v7-8" << col::RESET << " - Self-destruct mechanism for repeated failed key\n"
         << "       attempts; general refinement.\n";
    cout << col::BOLD << "v9.0" << col::RESET << " - Settings menu, key generation, key-file support,\n"
         << "       batch processing, search-while-browsing, recent\n"
         << "       files, command-line interface, optional master\n"
         << "       password, integrity checksums, statistics\n"
         << "       dashboard, and corrected retry handling for\n"
         << "       failed key attempts.\n";

    cout << col::RED << "\n----- SECURITY NOTICE -----\n" << col::RESET;
    cout << "This tool uses a simple XOR cipher for educational purposes.\n";
    cout << "  - Not intended for production-grade security. For real-world\n";
    cout << "    requirements, use an established standard such as AES\n";
    cout << "    (via OpenSSL or libsodium).\n";
    cout << "  - There is no password recovery mechanism by design. Losing\n";
    cout << "    the key makes the encrypted file permanently unrecoverable.\n";
    cout << "  - The plugin/update system compiles and executes code\n";
    cout << "    supplied by the user. This is a deliberate learning feature\n";
    cout << "    and should be treated as a code-execution capability, not\n";
    cout << "    exposed to untrusted users.\n";
    cout << "  - The optional master password uses a simple, non-\n";
    cout << "    cryptographic hash. It is a convenience lock, not a\n";
    cout << "    security boundary.\n";

    cout << col::CYAN << "\n----- DEVELOPER -----\n" << col::RESET;
    cout << "Name     : Muhammad Ali\n";
    cout << "Role     : Sole Developer\n";
    cout << "LinkedIn : https://www.linkedin.com/in/muhammad-ali-b5117641a\n";
    cout << "Email    : skyfighter15d@gmail.com\n";
    cout << "Phone/WA : +92 317 1275858\n";
    cout << col::MAGENTA << "\n===============================\n" << col::RESET;
}

void maybeShowRandomTip() {
    static vector<string> tips = {
        "Note: XOR-ing a value twice with the same key always returns the original value.",
        "Note: A key file (such as a private photo) functions the same as a typed password, but is longer and harder to guess.",
        "Note: A one-time random key as long as the file itself is called a 'one-time pad' and is theoretically unbreakable.",
        "Note: The Settings menu controls the default sort order and the optional master password.",
        "Note: Batch mode encrypts or decrypts an entire folder in one operation using a single key.",
        "Note: The activity log and Stats Dashboard both draw from the same recorded history."
    };
    static mt19937 rng(static_cast<unsigned>(time(nullptr)));
    uniform_int_distribution<int> chance(1, 100);
    if (chance(rng) <= 35) {
        uniform_int_distribution<int> pick(0, (int)tips.size() - 1);
        cout << col::YELLOW << "\n[" << tips[pick(rng)] << "]" << col::RESET << "\n";
    }
}

string resolveFileChoice(const vector<string>& names, const string& prompt);

// ---------- Plugin system (unchanged from v8) ----------
bool loadAndRunPlugin(const string& soPath) {
    void* handle = dlopen(soPath.c_str(), RTLD_LAZY);
    if (!handle) {
        cout << col::RED << "Failed to load plugin: " << dlerror() << col::RESET << "\n";
        return false;
    }
    dlerror();
    typedef void (*UpdateFunc)();
    UpdateFunc runUpdate = (UpdateFunc) dlsym(handle, "runUpdate");
    const char* dlsym_error = dlerror();
    if (dlsym_error) {
        cout << col::RED << "Plugin is missing a 'runUpdate' function: " << dlsym_error << col::RESET << "\n";
        dlclose(handle);
        return false;
    }
    cout << col::GREEN << "Running update:" << col::RESET << "\n";
    cout << col::YELLOW << "----------------------------------------\n" << col::RESET;
    runUpdate();
    cout << col::YELLOW << "----------------------------------------\n" << col::RESET;
    dlclose(handle);
    return true;
}

bool compileToSharedLib(const string& cppPath, const string& soPath, string& compilerUsed) {
    string compiler = detectCompiler();
    if (compiler.empty()) {
        cout << col::RED << "No C++ compiler found on this system (tried clang++ and g++).\n" << col::RESET;
        return false;
    }
    compilerUsed = compiler;
    string cmd = compiler + " -std=c++17 -shared -fPIC -o \"" + soPath + "\" \"" + cppPath + "\" 2> \""
                 + WORK_DIR + "compile_errors.log\"";
    cout << col::CYAN << "Compiling with " << compiler << " ..." << col::RESET << "\n";
    int result = std::system(cmd.c_str());
    if (result != 0) {
        cout << col::RED << "Compilation failed. Error details:\n" << col::RESET;
        ifstream errLog(WORK_DIR + "compile_errors.log");
        string line;
        while (getline(errLog, line)) cout << "  " << line << "\n";
        return false;
    }
    return true;
}

void writeUpdateFlow() {
    cout << col::CYAN << "\nWrite the C++ code that should run when this update executes.\n"
         << "Type your code, then on its own line type: ###END###\n" << col::RESET;
    cin.ignore();
    string line, body;
    while (true) {
        getline(cin, line);
        if (line == "###END###") break;
        body += line + "\n";
    }
    if (body.empty()) {
        cout << col::YELLOW << "No code entered -- cancelled.\n" << col::RESET;
        return;
    }
    string cppCode = "#include <iostream>\nusing namespace std;\nextern \"C\" void runUpdate() {\n" + body + "}\n";
    string cppPath = WORK_DIR + "src_update_temp.cpp";
    string soPath = PLUGIN_DIR + "update_" + timestampNow().substr(11,2) + timestampNow().substr(14,2)
                     + timestampNow().substr(17,2) + ".so";
    for (auto& c : soPath) if (c == ' ' || c == ':') c = '_';
    ofstream out(cppPath);
    out << cppCode;
    out.close();
    string compilerUsed;
    if (compileToSharedLib(cppPath, soPath, compilerUsed)) {
        cout << col::GREEN << "Compiled successfully with " << compilerUsed << ".\n" << col::RESET;
        logActivity("PLUGIN_WRITE_COMPILE", soPath, true);
        loadAndRunPlugin(soPath);
        logActivity("PLUGIN_RUN", soPath, true);
        cout << col::CYAN << "Saved permanently as: " << soPath << "\n" << col::RESET;
    } else {
        logActivity("PLUGIN_WRITE_COMPILE", cppPath, false);
    }
}

void importCppFileFlow() {
    cout << col::CYAN << "\nBrowse to the .cpp file you want to import:\n" << col::RESET;
    string cppPath = browseAndPickFile(STORAGE_ROOT);
    if (cppPath.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; return; }
    string filename = fs::path(cppPath).filename().string();
    string soName = filename;
    size_t dot = soName.find_last_of('.');
    if (dot != string::npos) soName = soName.substr(0, dot);
    string soPath = PLUGIN_DIR + soName + ".so";
    string compilerUsed;
    if (compileToSharedLib(cppPath, soPath, compilerUsed)) {
        cout << col::GREEN << "Compiled successfully with " << compilerUsed << ".\n" << col::RESET;
        logActivity("PLUGIN_IMPORT_COMPILE", filename, true);
        loadAndRunPlugin(soPath);
        logActivity("PLUGIN_RUN", soPath, true);
    } else {
        logActivity("PLUGIN_IMPORT_COMPILE", filename, false);
    }
}

void loadCompiledPluginFlow() {
    cout << col::CYAN << "\nLooking for plugins in: " << PLUGIN_DIR << col::RESET << "\n";
    vector<string> plugins;
    for (const auto& entry : fs::directory_iterator(PLUGIN_DIR)) {
        if (!entry.is_regular_file()) continue;
        string name = entry.path().filename().string();
        if (name.size() > 3 && name.substr(name.size() - 3) == ".so") {
            plugins.push_back(name);
            cout << "  " << col::BOLD << plugins.size() << col::RESET << ". " << name << "\n";
        }
    }
    if (plugins.empty()) {
        cout << col::YELLOW << "  (none found -- use option 1 or 2 to create one first)\n" << col::RESET;
        return;
    }
    string choice = resolveFileChoice(plugins, "\nEnter the number or filename of the plugin to load: ");
    string fullPath = PLUGIN_DIR + choice;
    if (!fs::exists(fullPath)) { cout << col::RED << "Plugin file not found.\n" << col::RESET; return; }
    bool success = loadAndRunPlugin(fullPath);
    logActivity("PLUGIN_LOAD", choice, success);
}

void importUpdateFlow() {
    cout << col::BOLD << "\n----- IMPORT UPDATE -----\n" << col::RESET;
    cout << "1. Write update code now (typed directly)\n";
    cout << "2. Import an existing .cpp file from storage\n";
    cout << "3. Load an already-compiled plugin (.so)\n";
    cout << "4. Back to main menu\n";
    cout << "Enter your choice: ";
    int sub = readMenuChoice();
    switch (sub) {
        case 1: writeUpdateFlow(); break;
        case 2: importCppFileFlow(); break;
        case 3: loadCompiledPluginFlow(); break;
        case 4: return;
        default: cout << col::RED << "Invalid choice.\n" << col::RESET;
    }
}

// Lists files in a folder with numbers, sorted per the saved setting (no prompt).
vector<string> listFilesNumbered(const string& folder, bool onlyEncFiles) {
    vector<fs::directory_entry> entries;
    for (const auto& entry : fs::directory_iterator(folder)) {
        if (!entry.is_regular_file()) continue;
        string name = entry.path().filename().string();
        if (name == "activity_log.txt" || name == "recent_files.txt" || name == "settings.txt") continue;
        if (onlyEncFiles) {
            if (name.size() < 4 || name.substr(name.size() - 4) != ".enc") continue;
        }
        entries.push_back(entry);
    }

    if (g_settings.sortOrder == 1) {
        sort(entries.begin(), entries.end(), [](const fs::directory_entry& a, const fs::directory_entry& b) {
            return a.path().filename().string() < b.path().filename().string();
        });
    } else if (g_settings.sortOrder == 2) {
        sort(entries.begin(), entries.end(), [](const fs::directory_entry& a, const fs::directory_entry& b) {
            return a.last_write_time() > b.last_write_time();
        });
    } else if (g_settings.sortOrder == 3) {
        sort(entries.begin(), entries.end(), [](const fs::directory_entry& a, const fs::directory_entry& b) {
            return a.file_size() > b.file_size();
        });
    }

    vector<string> names;
    cout << col::CYAN << "\nFiles in " << folder << ":" << col::RESET << "\n";
    for (const auto& entry : entries) {
        string name = entry.path().filename().string();
        names.push_back(name);
        cout << "  " << col::BOLD << names.size() << col::RESET << ". " << name
             << "  (" << humanReadableSize(entry.file_size()) << ")\n";
    }
    if (names.empty()) cout << "  (none found)\n";
    return names;
}

string resolveFileChoice(const vector<string>& names, const string& prompt) {
    cout << prompt;
    if (cin.peek() == '\n') cin.ignore();
    string input;
    getline(cin, input);
    bool isNumber = !input.empty() && input.find_first_not_of("0123456789") == string::npos;
    if (isNumber) {
        int idx = stoi(input);
        if (idx >= 1 && idx <= (int)names.size()) return names[idx - 1];
        cout << col::RED << "Invalid number, treating input as a filename instead.\n" << col::RESET;
    }
    return input;
}

// ---------- Key generation / key files ----------
string generateRandomKey(int length = 20) {
    static const string charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
    random_device rd;
    mt19937 rng(rd());
    uniform_int_distribution<int> dist(0, (int)charset.size() - 1);
    string key;
    for (int i = 0; i < length; i++) key += charset[dist(rng)];
    return key;
}

// Reads an entire file's bytes to use as a key. Returns "" on failure/empty.
string readKeyFile(const string& path) {
    ifstream f(path, ios::binary);
    if (!f) {
        cout << col::RED << "Could not open that file as a key file.\n" << col::RESET;
        return "";
    }
    string content((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
    if (content.empty()) {
        cout << col::RED << "That file is empty -- can't use it as a key.\n" << col::RESET;
        return "";
    }
    if (content.size() < 8) {
        cout << col::YELLOW << "Warning: that key file is very small (" << content.size()
             << " bytes). A bigger file makes a stronger key.\n" << col::RESET;
    }
    return content;
}

// Prompts for a key when ENCRYPTING. Loops in place on mismatch (bugfix)
// instead of bailing back to the menu. Returns "" only if the user cancels.
string getKeyForEncrypt() {
    while (true) {
        cout << col::CYAN << "\nHow do you want to provide the key?\n" << col::RESET;
        cout << "  1. Type a password\n";
        cout << "  2. Generate a strong random key for me\n";
        cout << "  3. Use a key file (any file as the key)\n";
        cout << "  4. Cancel\n";
        cout << "Enter your choice: ";
        int choice = readMenuChoice();

        if (choice == 1) {
            string key, keyConfirm;
            while (true) {
                cout << "Enter a secret key (no spaces, or type cancel to abort): ";
                cin >> key;
                if (key == "cancel") return "";
                cout << "Retype the key to confirm: ";
                cin >> keyConfirm;
                if (key == keyConfirm) break;
                cout << col::RED << "Keys didn't match -- let's try again.\n" << col::RESET;
            }
            if (key.size() < 8) {
                cout << col::YELLOW << "\nWarning: your key is short (" << key.size() << " characters). "
                     << "Consider a longer, more random key.\n" << col::RESET;
            }
            return key;
        } else if (choice == 2) {
            string key = generateRandomKey();
            cout << col::YELLOW << "\n===== YOUR GENERATED KEY (shown once) =====\n" << col::RESET;
            cout << col::BOLD << key << col::RESET << "\n";
            cout << col::RED << "WRITE THIS DOWN NOW. If you lose it, the file cannot be recovered.\n"
                 << col::RESET;
            cout << "Press Enter once you've saved it safely...";
            cin.ignore();
            string dummy;
            getline(cin, dummy);
            return key;
        } else if (choice == 3) {
            cout << col::CYAN << "\nBrowse to the file you want to use as your key:\n" << col::RESET;
            string keyPath = browseAndPickFile(STORAGE_ROOT);
            if (keyPath.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; continue; }
            string key = readKeyFile(keyPath);
            if (key.empty()) continue;
            cout << col::GREEN << "Using \"" << fs::path(keyPath).filename().string()
                 << "\" as your key. Keep this exact file safe -- you'll need it to decrypt.\n" << col::RESET;
            return key;
        } else if (choice == 4) {
            return "";
        } else {
            cout << col::RED << "Invalid choice.\n" << col::RESET;
        }
    }
}

// Prompts for a key when DECRYPTING. Returns "" if the user cancels.
string getKeyForDecrypt() {
    while (true) {
        cout << col::CYAN << "\nHow do you want to provide the key?\n" << col::RESET;
        cout << "  1. Type the password\n";
        cout << "  2. Use a key file\n";
        cout << "  3. Cancel\n";
        cout << "Enter your choice: ";
        int choice = readMenuChoice();

        if (choice == 1) {
            cout << "Enter the secret key you used to encrypt it: ";
            string key;
            cin >> key;
            if (key.empty()) { cout << col::RED << "Key cannot be empty.\n" << col::RESET; continue; }
            return key;
        } else if (choice == 2) {
            cout << col::CYAN << "\nBrowse to the key file:\n" << col::RESET;
            string keyPath = browseAndPickFile(STORAGE_ROOT);
            if (keyPath.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; continue; }
            string key = readKeyFile(keyPath);
            if (key.empty()) continue;
            return key;
        } else if (choice == 3) {
            return "";
        } else {
            cout << col::RED << "Invalid choice.\n" << col::RESET;
        }
    }
}

// ---------- Checksum helpers (integrity checking) ----------
void writeUint32BE_XOR(ofstream& out, uint32_t val, const string& key, size_t& keyIndex) {
    for (int i = 3; i >= 0; i--) {
        char b = (char)((val >> (i * 8)) & 0xFF);
        out.put(b ^ key[keyIndex]);
        keyIndex = (keyIndex + 1) % key.size();
    }
}
uint32_t readUint32BE_XOR(ifstream& in, const string& key, size_t& keyIndex, bool& ok) {
    uint32_t val = 0;
    for (int i = 0; i < 4; i++) {
        char b;
        if (!in.get(b)) { ok = false; return 0; }
        unsigned char decoded = (unsigned char)(b ^ key[keyIndex]);
        keyIndex = (keyIndex + 1) % key.size();
        val = (val << 8) | decoded;
    }
    ok = true;
    return val;
}

// ---------- Core encrypt / decrypt (v9: adds integrity checksum) ----------
bool encryptFileXOR(const string& inputPath, const string& outputPath, const string& key) {
    ifstream inFile(inputPath, ios::binary);
    if (!inFile) {
        cout << col::RED << "Error: Could not open \"" << inputPath << "\"" << col::RESET << "\n";
        return false;
    }
    vector<char> buffer((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
    inFile.close();

    uint32_t checksum = FNV_OFFSET;
    for (unsigned char c : buffer) { checksum ^= c; checksum *= FNV_PRIME; }

    ofstream outFile(outputPath, ios::binary);
    if (!outFile) {
        cout << col::RED << "Error: Could not create \"" << outputPath << "\"" << col::RESET << "\n";
        return false;
    }

    size_t keyIndex = 0;
    for (char m : MAGIC_SIGNATURE) {
        outFile.put(m ^ key[keyIndex]);
        keyIndex = (keyIndex + 1) % key.size();
    }
    writeUint32BE_XOR(outFile, checksum, key, keyIndex);

    uintmax_t totalSize = buffer.size();
    uintmax_t processed = 0;
    int lastPercentShown = -1;

    for (char byte : buffer) {
        outFile.put(byte ^ key[keyIndex]);
        keyIndex = (keyIndex + 1) % key.size();
        processed++;
        if (totalSize > 0) {
            int percent = (int)((processed * 100) / totalSize);
            if (percent != lastPercentShown && percent % 10 == 0) {
                lastPercentShown = percent;
                cout << "\r" << col::CYAN << "Progress: [" << string(percent/5, '#')
                     << string(20 - percent/5, '-') << "] " << percent << "%" << col::RESET << flush;
            }
        }
    }
    cout << "\r" << col::CYAN << "Progress: [####################] 100%" << col::RESET << "\n";
    outFile.close();
    cout << col::GREEN << humanReadableSize(processed) << " processed." << col::RESET << "\n";
    return true;
}

enum class DecryptResult { SUCCESS, WRONG_KEY, IO_ERROR };

DecryptResult decryptFileXOR(const string& inputPath, const string& outputPath, const string& key) {
    ifstream inFile(inputPath, ios::binary);
    if (!inFile) {
        cout << col::RED << "Error: Could not open \"" << inputPath << "\"" << col::RESET << "\n";
        return DecryptResult::IO_ERROR;
    }

    size_t keyIndex = 0;
    string decodedMagic;
    char byte;
    for (size_t i = 0; i < MAGIC_SIGNATURE.size(); i++) {
        if (!inFile.get(byte)) {
            cout << col::RED << "File is too small/corrupted to be a valid encrypted file.\n" << col::RESET;
            return DecryptResult::IO_ERROR;
        }
        decodedMagic += (byte ^ key[keyIndex]);
        keyIndex = (keyIndex + 1) % key.size();
    }
    if (decodedMagic != MAGIC_SIGNATURE) {
        return DecryptResult::WRONG_KEY; // nothing written yet
    }

    bool ok;
    uint32_t storedChecksum = readUint32BE_XOR(inFile, key, keyIndex, ok);
    if (!ok) {
        cout << col::RED << "File is too small/corrupted to be a valid encrypted file.\n" << col::RESET;
        return DecryptResult::IO_ERROR;
    }

    ofstream outFile(outputPath, ios::binary);
    if (!outFile) {
        cout << col::RED << "Error: Could not create \"" << outputPath << "\"" << col::RESET << "\n";
        return DecryptResult::IO_ERROR;
    }

    uintmax_t totalSize = fs::file_size(inputPath);
    uintmax_t headerSize = MAGIC_SIGNATURE.size() + 4;
    uintmax_t remaining = totalSize > headerSize ? totalSize - headerSize : 0;
    uintmax_t processed = 0;
    int lastPercentShown = -1;
    uint32_t computedChecksum = FNV_OFFSET;

    while (inFile.get(byte)) {
        unsigned char decoded = (unsigned char)(byte ^ key[keyIndex]);
        keyIndex = (keyIndex + 1) % key.size();
        outFile.put((char)decoded);
        computedChecksum ^= decoded;
        computedChecksum *= FNV_PRIME;
        processed++;
        if (remaining > 0) {
            int percent = (int)((processed * 100) / remaining);
            if (percent != lastPercentShown && percent % 10 == 0) {
                lastPercentShown = percent;
                cout << "\r" << col::CYAN << "Progress: [" << string(percent/5, '#')
                     << string(20 - percent/5, '-') << "] " << percent << "%" << col::RESET << flush;
            }
        }
    }
    cout << "\r" << col::CYAN << "Progress: [####################] 100%" << col::RESET << "\n";
    outFile.close();
    cout << col::GREEN << humanReadableSize(processed) << " processed." << col::RESET << "\n";

    if (computedChecksum != storedChecksum) {
        cout << col::YELLOW << col::BOLD
             << "\nINTEGRITY WARNING: the key was correct, but this file's contents don't\n"
             << "match its stored checksum. It may have been corrupted or altered after\n"
             << "encryption. The restored file was still written -- check it carefully.\n"
             << col::RESET;
        logActivity("INTEGRITY_WARNING", outputPath, false);
    }
    return DecryptResult::SUCCESS;
}

bool confirmOverwriteIfNeeded(const string& path) {
    if (!fs::exists(path)) return true;
    cout << col::YELLOW << "A file already exists at \"" << path << "\". Overwrite? (y/n): " << col::RESET;
    char c;
    cin >> c;
    return (c == 'y' || c == 'Y');
}

void destroyFile(const string& path) {
    if (!fs::exists(path)) return;
    uintmax_t size = fs::file_size(path);
    ofstream f(path, ios::binary | ios::trunc);
    static mt19937 rng(static_cast<unsigned>(time(nullptr)));
    uniform_int_distribution<int> dist(0, 255);
    for (uintmax_t i = 0; i < size; i++) f.put((char)dist(rng));
    f.close();
    fs::remove(path);
}

// ---------- Single-file encrypt ----------
void encryptSingleFlow() {
    cout << col::CYAN << "\nBrowse to the file you want to encrypt (from anywhere in storage):\n" << col::RESET;
    string inputPath = browseAndPickFile(STORAGE_ROOT);
    if (inputPath.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; return; }

    string filename = fs::path(inputPath).filename().string();
    string key = getKeyForEncrypt();
    if (key.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; return; }

    string outputPath = WORK_DIR + filename + ".enc";
    if (!confirmOverwriteIfNeeded(outputPath)) { cout << "Cancelled.\n"; return; }

    long long sizeBefore = (long long)fs::file_size(inputPath);
    bool success = encryptFileXOR(inputPath, outputPath, key);
    logActivity("ENCRYPT", filename, success, success ? sizeBefore : -1);

    if (success) {
        saveOriginalLocation(filename + ".enc", inputPath);
        resetFailedAttempts(hashPath(outputPath));
        addRecentFile("ENCRYPT", filename + ".enc");
        cout << col::GREEN << "Encrypted file saved to: " << outputPath << col::RESET << "\n";
        cout << "(Your original file was left untouched.)\n";
    }
}

// ---------- Wrong-key retry now loops in place (bugfix) ----------
void attemptDecrypt(const string& inputPath, const string& suggestedFinalPath) {
    string fileId = hashPath(inputPath);

    while (true) {
        int attemptsSoFar = getFailedAttempts(fileId);
        if (attemptsSoFar >= MAX_ATTEMPTS) {
            cout << col::RED << "This file already reached the maximum failed attempts and "
                 << "should no longer exist.\n" << col::RESET;
            return;
        }

        string key = getKeyForDecrypt();
        if (key.empty()) { cout << "Cancelled.\n"; return; }

        string tempOutput = WORK_DIR + "restored_" + fs::path(suggestedFinalPath).filename().string();
        DecryptResult result = decryptFileXOR(inputPath, tempOutput, key);

        if (result == DecryptResult::SUCCESS) {
            if (!confirmOverwriteIfNeeded(suggestedFinalPath)) {
                fs::remove(tempOutput);
                cout << "Cancelled.\n";
                return;
            }
            fs::rename(tempOutput, suggestedFinalPath);
            resetFailedAttempts(fileId);
            long long sz = fs::exists(suggestedFinalPath) ? (long long)fs::file_size(suggestedFinalPath) : -1;
            logActivity("DECRYPT", inputPath, true, sz);
            addRecentFile("DECRYPT", fs::path(suggestedFinalPath).filename().string());
            cout << col::GREEN << "Decrypted and restored to: " << suggestedFinalPath << col::RESET << "\n";
            return;

        } else if (result == DecryptResult::WRONG_KEY) {
            attemptsSoFar++;
            setFailedAttempts(fileId, attemptsSoFar);
            int remaining = MAX_ATTEMPTS - attemptsSoFar;
            logActivity("DECRYPT_WRONG_KEY", inputPath, false);

            if (remaining > 0) {
                cout << col::RED << "\nWrong key -- no file was corrupted or changed.\n" << col::RESET;
                cout << col::YELLOW << remaining << " attempt(s) remaining before this file "
                     << "self-destructs. Let's try again:\n" << col::RESET;
                continue; // <-- retry right here instead of bouncing to the main menu
            } else {
                destroyFile(inputPath);
                resetFailedAttempts(fileId);
                logActivity("SELF_DESTRUCT", inputPath, true);
                cout << col::RED << col::BOLD
                     << "\nSECURITY: 5 failed key attempts reached.\n"
                     << "This file has been permanently destroyed and cannot be recovered.\n"
                     << col::RESET;
                return;
            }
        } else {
            logActivity("DECRYPT_ERROR", inputPath, false);
            return;
        }
    }
}

void decryptKnownFile(const string& filename) {
    string inputPath = WORK_DIR + filename;
    if (!fs::exists(inputPath)) {
        cout << col::RED << "That file wasn't found in the FileEncryptor folder.\n" << col::RESET;
        return;
    }
    string restoredName = filename;
    if (restoredName.size() > 4 && restoredName.substr(restoredName.size() - 4) == ".enc") {
        restoredName = restoredName.substr(0, restoredName.size() - 4);
    }
    string originalPath = loadOriginalLocation(filename);
    string finalPath;
    if (!originalPath.empty()) {
        finalPath = originalPath;
        fs::create_directories(fs::path(finalPath).parent_path());
    } else {
        finalPath = STORAGE_ROOT + restoredName;
        cout << col::YELLOW << "No original location on record -- restoring to main storage folder.\n"
             << col::RESET;
    }
    attemptDecrypt(inputPath, finalPath);
}

void decryptInternalFlow() {
    auto names = listFilesNumbered(WORK_DIR, true);
    if (names.empty()) return;
    string filename = resolveFileChoice(names, "\nEnter the number or .enc filename to decrypt: ");
    decryptKnownFile(filename);
}

void decryptExternalFlow() {
    cout << col::CYAN << "\nBrowse to the .enc file you want to decrypt (from anywhere):\n" << col::RESET;
    string inputPath = browseAndPickFile(STORAGE_ROOT);
    if (inputPath.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; return; }

    string filename = fs::path(inputPath).filename().string();
    if (!(filename.size() > 4 && filename.substr(filename.size() - 4) == ".enc")) {
        cout << col::YELLOW << "Note: this file doesn't end in \".enc\" -- proceeding anyway.\n" << col::RESET;
    }
    string restoredName = filename;
    if (restoredName.size() > 4 && restoredName.substr(restoredName.size() - 4) == ".enc") {
        restoredName = restoredName.substr(0, restoredName.size() - 4);
    }
    string originalPath = loadOriginalLocation(filename);
    string finalPath;
    if (!originalPath.empty()) {
        finalPath = originalPath;
        fs::create_directories(fs::path(finalPath).parent_path());
    } else {
        finalPath = fs::path(inputPath).parent_path().string() + "/" + restoredName;
    }
    attemptDecrypt(inputPath, finalPath);
}

void decryptFromRecentFlow() {
    vector<string> lines = readRecentFiles();
    showRecentFilesFlow();
    if (lines.empty()) return;
    cout << "\nEnter the number of the entry to decrypt (must be an ENCRYPT entry), or 0 to cancel: ";
    int choice = readMenuChoice();
    if (choice < 1 || choice > (int)lines.size()) { cout << "Cancelled.\n"; return; }

    stringstream ss(lines[choice - 1]);
    string ts, action, filename;
    getline(ss, ts, '|');
    getline(ss, action, '|');
    getline(ss, filename, '|');

    if (action != "ENCRYPT") {
        cout << col::RED << "That entry isn't an encrypted file -- pick one marked [ENCRYPT].\n" << col::RESET;
        return;
    }
    decryptKnownFile(filename);
}

void decryptFlow() {
    cout << col::BOLD << "\n----- DECRYPT -----\n" << col::RESET;
    cout << "1. Decrypt a file from the FileEncryptor archive\n";
    cout << "2. Decrypt an external .enc file (from anywhere in storage)\n";
    cout << "3. Batch decrypt a whole folder\n";
    cout << "4. Decrypt from Recent Files\n";
    cout << "5. Back to main menu\n";
    cout << "Enter your choice: ";
    int sub = readMenuChoice();
    switch (sub) {
        case 1: decryptInternalFlow(); break;
        case 2: decryptExternalFlow(); break;
        case 3: /* filled in below after declaration */ break;
        case 4: decryptFromRecentFlow(); break;
        case 5: return;
        default: cout << col::RED << "Invalid choice.\n" << col::RESET;
    }
}

// ---------- Batch mode ----------
void batchEncryptFlow() {
    cout << col::CYAN << "\nBrowse to the folder you want to batch-encrypt:\n" << col::RESET;
    string folder = browseAndPickFile(STORAGE_ROOT, true);
    if (folder.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; return; }

    string key = getKeyForEncrypt();
    if (key.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; return; }

    int successCount = 0, failCount = 0;
    for (const auto& entry : fs::directory_iterator(folder)) {
        if (!entry.is_regular_file()) continue;
        string filename = entry.path().filename().string();
        string inputPath = entry.path().string();
        string outputPath = WORK_DIR + filename + ".enc";

        if (fs::exists(outputPath)) {
            cout << col::YELLOW << "Skipping \"" << filename << "\" -- already encrypted in archive.\n"
                 << col::RESET;
            continue;
        }

        long long sz = (long long)fs::file_size(inputPath);
        bool ok = encryptFileXOR(inputPath, outputPath, key);
        logActivity("ENCRYPT_BATCH", filename, ok, ok ? sz : -1);
        if (ok) {
            saveOriginalLocation(filename + ".enc", inputPath);
            addRecentFile("ENCRYPT", filename + ".enc");
            successCount++;
        } else {
            failCount++;
        }
    }
    cout << col::GREEN << "\nBatch encrypt complete: " << successCount << " succeeded, "
         << failCount << " failed.\n" << col::RESET;
}

void batchDecryptFlow() {
    cout << col::CYAN << "\nBrowse to the folder containing the .enc files to decrypt:\n" << col::RESET;
    string folder = browseAndPickFile(STORAGE_ROOT, true);
    if (folder.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; return; }

    string key = getKeyForDecrypt();
    if (key.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; return; }

    cout << col::YELLOW << "Note: batch mode applies one key to every file and does not use the "
         << "5-attempt self-destruct lock -- wrong-key files are simply skipped.\n" << col::RESET;

    int successCount = 0, wrongKeyCount = 0, failCount = 0;
    for (const auto& entry : fs::directory_iterator(folder)) {
        if (!entry.is_regular_file()) continue;
        string filename = entry.path().filename().string();
        if (!(filename.size() > 4 && filename.substr(filename.size() - 4) == ".enc")) continue;

        string inputPath = entry.path().string();
        string restoredName = filename.substr(0, filename.size() - 4);
        string outputPath = folder + "/" + restoredName;

        if (fs::exists(outputPath)) {
            cout << col::YELLOW << "Skipping \"" << filename << "\" -- \"" << restoredName
                 << "\" already exists there.\n" << col::RESET;
            continue;
        }

        DecryptResult result = decryptFileXOR(inputPath, outputPath, key);
        if (result == DecryptResult::SUCCESS) {
            long long sz = (long long)fs::file_size(outputPath);
            logActivity("DECRYPT_BATCH", filename, true, sz);
            addRecentFile("DECRYPT", restoredName);
            successCount++;
        } else if (result == DecryptResult::WRONG_KEY) {
            logActivity("DECRYPT_BATCH_WRONG_KEY", filename, false);
            wrongKeyCount++;
        } else {
            logActivity("DECRYPT_BATCH_ERROR", filename, false);
            failCount++;
        }
    }
    cout << col::GREEN << "\nBatch decrypt complete: " << successCount << " succeeded, "
         << col::RESET << wrongKeyCount << " wrong-key, " << failCount << " errors.\n";
}

void encryptFlow() {
    cout << col::BOLD << "\n----- ENCRYPT -----\n" << col::RESET;
    cout << "1. Encrypt a single file\n";
    cout << "2. Batch encrypt a whole folder\n";
    cout << "3. Back to main menu\n";
    cout << "Enter your choice: ";
    int sub = readMenuChoice();
    switch (sub) {
        case 1: encryptSingleFlow(); break;
        case 2: batchEncryptFlow(); break;
        case 3: return;
        default: cout << col::RED << "Invalid choice.\n" << col::RESET;
    }
}

// ---------- Settings ----------
void changeSortOrderSetting() {
    cout << col::CYAN << "\nCurrent default sort order: " << col::RESET;
    if (g_settings.sortOrder == 1) cout << "Name\n";
    else if (g_settings.sortOrder == 2) cout << "Date modified (newest first)\n";
    else cout << "Size (largest first)\n";

    cout << "1) Name  2) Date modified  3) Size  -- choose new default: ";
    int choice = readMenuChoice();
    if (choice >= 1 && choice <= 3) {
        g_settings.sortOrder = choice;
        saveSettings();
        cout << col::GREEN << "Saved.\n" << col::RESET;
    } else {
        cout << col::RED << "Invalid choice -- left unchanged.\n" << col::RESET;
    }
}

void toggleMasterPassword() {
    if (!g_settings.masterPasswordEnabled) {
        cout << col::CYAN << "\nSet a master password to require it before the menu opens.\n" << col::RESET;
        cout << "Enter a new master password (leave blank to cancel): ";
        cin.ignore();
        string pw;
        getline(cin, pw);
        if (pw.empty()) { cout << col::YELLOW << "Cancelled.\n" << col::RESET; return; }
        g_settings.masterPasswordHash = simpleHash(pw);
        g_settings.masterPasswordEnabled = true;
        saveSettings();
        cout << col::GREEN << "Master password lock enabled.\n" << col::RESET;
    } else {
        cout << "Enter your current master password to disable the lock: ";
        cin.ignore();
        string pw;
        getline(cin, pw);
        if (simpleHash(pw) == g_settings.masterPasswordHash) {
            g_settings.masterPasswordEnabled = false;
            g_settings.masterPasswordHash = "";
            saveSettings();
            cout << col::GREEN << "Master password lock disabled.\n" << col::RESET;
        } else {
            cout << col::RED << "Incorrect password -- lock left enabled.\n" << col::RESET;
        }
    }
}

void settingsFlow() {
    while (true) {
        cout << col::BOLD << "\n----- SETTINGS -----\n" << col::RESET;
        cout << "1. Change default file-list sort order\n";
        cout << "2. " << (g_settings.masterPasswordEnabled ? "Disable" : "Enable")
             << " master password lock\n";
        cout << "3. Back to main menu\n";
        cout << "Enter your choice: ";
        int choice = readMenuChoice();
        if (choice == 1) changeSortOrderSetting();
        else if (choice == 2) toggleMasterPassword();
        else if (choice == 3) return;
        else cout << col::RED << "Invalid choice.\n" << col::RESET;
    }
}

bool checkMasterPasswordAtStartup() {
    if (!g_settings.masterPasswordEnabled) return true;
    int tries = 0;
    while (tries < 3) {
        cout << col::CYAN << "This app is locked. Enter master password: " << col::RESET;
        string pw;
        cin.ignore();
        getline(cin, pw);
        if (simpleHash(pw) == g_settings.masterPasswordHash) return true;
        tries++;
        cout << col::RED << "Incorrect. " << (3 - tries) << " attempt(s) left.\n" << col::RESET;
    }
    cout << col::RED << "Too many failed attempts. Exiting.\n" << col::RESET;
    return false;
}

// ---------- Stats dashboard ----------
void showStatsDashboard() {
    ifstream log(LOG_FILE);
    if (!log) {
        cout << col::YELLOW << "No activity logged yet.\n" << col::RESET;
        return;
    }
    int encryptSuccess = 0, decryptSuccess = 0, totalLines = 0;
    long long totalBytesEncrypted = 0;
    map<string, int> dayCounts;

    string line;
    while (getline(log, line)) {
        if (line.size() < 12 || line[0] != '[') continue;
        totalLines++;
        string date = line.substr(1, 10);
        dayCounts[date]++;

        bool success = line.find("SUCCESS") != string::npos;
        bool isEncrypt = line.find("ENCRYPT") != string::npos && line.find("WRONG") == string::npos;
        bool isDecrypt = line.find("DECRYPT") != string::npos && line.find("WRONG") == string::npos
                          && line.find("ERROR") == string::npos;

        if (success && isEncrypt) {
            encryptSuccess++;
            size_t sizePos = line.find("SIZE:");
            if (sizePos != string::npos) {
                try { totalBytesEncrypted += stoll(line.substr(sizePos + 5)); } catch (...) {}
            }
        }
        if (success && isDecrypt) decryptSuccess++;
    }

    string busiestDay = "-";
    int busiestCount = 0;
    for (auto& kv : dayCounts) {
        if (kv.second > busiestCount) { busiestCount = kv.second; busiestDay = kv.first; }
    }

    cout << col::CYAN << "\n----- STATS DASHBOARD -----\n" << col::RESET;
    cout << "Files encrypted successfully : " << encryptSuccess << "\n";
    cout << "Files decrypted successfully : " << decryptSuccess << "\n";
    cout << "Total data protected         : " << humanReadableSize((uintmax_t)totalBytesEncrypted) << "\n";
    cout << "Total log entries            : " << totalLines << "\n";
    if (busiestCount > 0) {
        cout << "Most active day               : " << busiestDay << " (" << busiestCount << " actions)\n";
    }
    cout << col::CYAN << "----------------------------\n" << col::RESET;
}

void showActivityLog() {
    ifstream log(LOG_FILE);
    if (!log) {
        cout << col::YELLOW << "No activity logged yet.\n" << col::RESET;
        return;
    }
    cout << col::CYAN << "\n----- ACTIVITY LOG -----\n" << col::RESET;
    string line;
    while (getline(log, line)) cout << line << "\n";
    cout << col::CYAN << "-------------------------\n" << col::RESET;
}

void printMenu() {
    cout << col::BOLD << "\n===== FILE ENCRYPTOR / DECRYPTOR v9 =====\n" << col::RESET;
    cout << "1. Encrypt\n";
    cout << "2. Decrypt\n";
    cout << "3. View activity log\n";
    cout << "4. Recent files\n";
    cout << "5. Stats dashboard\n";
    cout << "6. About / Developer Info\n";
    cout << "7. Import Update (load a plugin)\n";
    cout << "8. Settings\n";
    cout << "9. Exit\n";
    cout << "Enter your choice: ";
}

// ---------- CLI mode ----------
int runCliMode(int argc, char* argv[]) {
    string mode = argv[1];
    if ((mode != "encrypt" && mode != "decrypt") || argc < 4) {
        cout << "Usage:\n"
             << "  ./encryptor encrypt <file> <key>\n"
             << "  ./encryptor decrypt <file> <key>\n"
             << "  ./encryptor                (interactive menu)\n";
        return 1;
    }
    string filePath = argv[2];
    string key = argv[3];

    if (!fs::exists(filePath)) {
        cerr << "Error: file not found: " << filePath << "\n";
        return 1;
    }

    if (mode == "encrypt") {
        string filename = fs::path(filePath).filename().string();
        string outputPath = WORK_DIR + filename + ".enc";
        long long sz = (long long)fs::file_size(filePath);
        bool ok = encryptFileXOR(filePath, outputPath, key);
        logActivity("ENCRYPT_CLI", filename, ok, ok ? sz : -1);
        if (ok) {
            saveOriginalLocation(filename + ".enc", filePath);
            addRecentFile("ENCRYPT", filename + ".enc");
            cout << col::GREEN << "Encrypted to: " << outputPath << col::RESET << "\n";
            return 0;
        }
        return 1;
    } else {
        string filename = fs::path(filePath).filename().string();
        string restoredName = filename;
        if (restoredName.size() > 4 && restoredName.substr(restoredName.size() - 4) == ".enc") {
            restoredName = restoredName.substr(0, restoredName.size() - 4);
        }
        string outputPath = fs::path(filePath).parent_path().string() + "/" + restoredName;
        DecryptResult r = decryptFileXOR(filePath, outputPath, key);
        if (r == DecryptResult::SUCCESS) {
            logActivity("DECRYPT_CLI", filename, true, (long long)fs::file_size(outputPath));
            addRecentFile("DECRYPT", restoredName);
            cout << col::GREEN << "Decrypted to: " << outputPath << col::RESET << "\n";
            return 0;
        } else if (r == DecryptResult::WRONG_KEY) {
            cerr << "Wrong key.\n";
            logActivity("DECRYPT_CLI", filename, false);
            return 1;
        } else {
            logActivity("DECRYPT_CLI", filename, false);
            return 1;
        }
    }
}

int main(int argc, char* argv[]) {
    ensureWorkDirExists();
    loadSettings();

    if (argc > 1) {
        return runCliMode(argc, argv);
    }

    cout << col::CYAN << "Working folder: " << WORK_DIR << col::RESET << "\n";

    if (!checkMasterPasswordAtStartup()) return 0;

    int choice;
    do {
        maybeShowRandomTip();
        printMenu();
        choice = readMenuChoice();

        switch (choice) {
            case 1: encryptFlow(); break;
            case 2: {
                // decryptFlow's batch case is wired here directly to avoid
                // forward-declaring batchDecryptFlow above its definition.
                cout << col::BOLD << "\n----- DECRYPT -----\n" << col::RESET;
                cout << "1. Decrypt a file from the FileEncryptor archive\n";
                cout << "2. Decrypt an external .enc file (from anywhere in storage)\n";
                cout << "3. Batch decrypt a whole folder\n";
                cout << "4. Decrypt from Recent Files\n";
                cout << "5. Back to main menu\n";
                cout << "Enter your choice: ";
                int sub = readMenuChoice();
                switch (sub) {
                    case 1: decryptInternalFlow(); break;
                    case 2: decryptExternalFlow(); break;
                    case 3: batchDecryptFlow(); break;
                    case 4: decryptFromRecentFlow(); break;
                    case 5: break;
                    default: cout << col::RED << "Invalid choice.\n" << col::RESET;
                }
                break;
            }
            case 3: showActivityLog(); break;
            case 4: showRecentFilesFlow(); break;
            case 5: showStatsDashboard(); break;
            case 6: showDeveloperInfo(); break;
            case 7: importUpdateFlow(); break;
            case 8: settingsFlow(); break;
            case 9: cout << col::GREEN << "Goodbye!\n" << col::RESET; break;
            default: cout << col::RED << "Invalid choice, try again.\n" << col::RESET;
        }
    } while (choice != 9);

    return 0;
}
