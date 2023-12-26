#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <set>

#include <ctype.h>
#include <string.h>
#include <stdlib.h>


// Minimalistic ini file parsing routines that are intended to be safe to use
// from DllMain. Should be fairly fast since they don't update our usual data
// structures and don't do any unecessary backtracking while scanning for the
// queried setting, which will help minimise the time we stall newly spawned
// processes we may have been injected into that are not our intended target.


//�����ַ����еĿո���Ʊ�������ص�һ���ǿո�ͷ��Ʊ���ַ���λ�á�
static const char* skip_space(const char* buf)
{
	for (; *buf == ' ' || *buf == '\t'; buf++) {}
	return buf;
}

// Returns a pointer to the next non-whitespace character on a following line
static const char* next_line(const char* buf)
{
	for (; *buf != '\0' && *buf != '\n' && *buf != '\r'; buf++) {}
	for (; *buf == '\n' || *buf == '\r' || *buf == ' ' || *buf == '\t'; buf++) {}
	return buf;
}

// Returns a pointer to the first non-whitespace character on the line
// following [section_name] (which may be a pointer to the zero terminator if
// EOF is encountered), or NULL if the section is not found. section_name must
// be lower case.
const char* find_ini_section_lite(const char* buf, const char* section_name)
{
	const char* p;

	for (buf = skip_space(buf); *buf; buf = next_line(buf)) {
		if (*buf == '[') {
			for (buf++, p = section_name; *p && (tolower((unsigned char)*buf) == *p); buf++, p++) {}
			if (*buf == ']' && *p == '\0')
				return next_line(buf);
		}
	}

	return 0;
}

// Searches for the setting. If found in the current section, copies the value
// to ret stripping any whitespace from the end of line and returns true. If
// not found or the buffer size is insufficient, returns false.
bool find_ini_setting_lite(const char* buf, const char* setting, char* ret, size_t n)
{
	const char* p;
	char* r;
	size_t i;

	for (buf = skip_space(buf); *buf; buf = next_line(buf)) {
		// Check for end of section
		if (*buf == '[')
			return false;

		// Check if line matches setting
		for (p = setting; *p && tolower((unsigned char)*buf) == *p; buf++, p++) {}
		buf = skip_space(buf);
		if (*buf != '=' || *p != '\0')
			continue;

		// Copy setting until EOL/EOF to ret buffer
		buf = skip_space(buf + 1);
		for (i = 0, r = ret; i < n; i++, buf++, r++) {
			*r = *buf;
			if (*buf == '\n' || *buf == '\r' || *buf == '\0') {
				// Null terminate return buffer and strip any whitespace from EOL:
				for (; r >= ret && (*r == '\0' || *r == '\n' || *r == '\r' || *r == ' ' || *r == '\t'); r--)
					*r = '\0';
				return true;
			}
		}
		// Insufficient room in buffer
		return false;
	}
	return false;
}

bool find_ini_bool_lite(const char* buf, const char* setting, bool def)
{
	char val[8];

	if (!find_ini_setting_lite(buf, setting, val, 8))
		return def;

	if (!_stricmp(val, "1") || !_stricmp(val, "true") || !_stricmp(val, "yes") || !_stricmp(val, "on"))
		return true;

	if (!_stricmp(val, "0") || !_stricmp(val, "false") || !_stricmp(val, "no") || !_stricmp(val, "off"))
		return false;

	return def;
}


int find_ini_int_lite(const char* buf, const char* setting, int def)
{
	char val[16];

	if (!find_ini_setting_lite(buf, setting, val, 16))
		return def;

	return atoi(val);
}


// ���庯��
std::wstring GetCurrentWorkingDirectory()
{
	std::wstring workingDir;
	wchar_t buffer[MAX_PATH];

	DWORD ret = GetCurrentDirectory(MAX_PATH, buffer);
	if (ret == 0)
	{
		// ��ȡ·��ʧ�ܣ��������򷵻ؿյ�wstring
		return std::wstring();
	}
	// ���ذ�����ǰ����Ŀ¼·����wstring
	return std::wstring(buffer);
}


std::wstring to_wide_string(std::string input) {
	if (input.empty()) return L"";

	int size_needed = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, NULL, 0);
	if (size_needed == 0) {
		// Handle error appropriately
		throw std::runtime_error("Failed in MultiByteToWideChar conversion.");
	}

	std::wstring wstrTo(size_needed, L'\0');
	int chars_converted = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &wstrTo[0], size_needed);
	if (chars_converted == 0) {
		// Handle error appropriately
		throw std::runtime_error("Failed in MultiByteToWideChar conversion.");
	}

	// Remove the null terminator as it is implicitly handled in std::wstring
	wstrTo.pop_back();

	return wstrTo;
}


std::string to_byte_string(std::wstring input) {
	if (input.empty()) return "";

	int size_needed = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, NULL, 0, NULL, NULL);
	if (size_needed == 0) {
		// Handle error appropriately
		throw std::runtime_error("Failed in WideCharToMultiByte conversion.");
	}

	std::string strTo(size_needed, '\0');
	int bytes_converted = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &strTo[0], size_needed, NULL, NULL);
	if (bytes_converted == 0) {
		// Handle error appropriately
		throw std::runtime_error("Failed in WideCharToMultiByte conversion.");
	}

	// Remove the null terminator as it is implicitly handled in std::string
	strTo.pop_back();

	return strTo;
}


static void wait_keypress(const char* msg)
{
	puts(msg);
	getchar();
}

static void wait_exit(int code = 0, char* msg = _strdup("\nPress enter to close...\n"))
{
	wait_keypress(msg);
	exit(code);
}

static void exit_usage(const char* msg)
{
	//                                                          80 column limit --------> \n
	printf("The Loader is not configured correctly. Please copy the 3DMigoto d3d11.dll\n"
		"and d3dx.ini into this directory, then edit the d3dx.ini's [Loader] section\n"
		"to set the target executable and 3DMigoto module name.\n"
		"\n"
		"%s", msg);

	wait_exit(EXIT_FAILURE);
}


static bool verify_injection(PROCESSENTRY32* pe, const wchar_t* module, bool log_name)
{
	HANDLE snapshot;
	MODULEENTRY32 me;
	const wchar_t* basename = wcsrchr(module, '\\');
	bool rc = false;
	static std::set<DWORD> pids;
	wchar_t exe_path[MAX_PATH], mod_path[MAX_PATH];

	if (basename)
		basename++;
	else
		basename = module;

	do {
		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe->th32ProcessID);
	} while (snapshot == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("%S (%d): Unable to verify if 3DMigoto was successfully loaded: %d\n",
			pe->szExeFile, pe->th32ProcessID, GetLastError());
		return false;
	}

	me.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(snapshot, &me)) {
		printf("%S (%d): Unable to verify if 3DMigoto was successfully loaded: %d\n",
			pe->szExeFile, pe->th32ProcessID, GetLastError());
		goto out_close;
	}

	// First module is the executable, and this is how we get the full path:
	if (log_name)
		printf("Target process found (%i): %S\n", pe->th32ProcessID, me.szExePath);
	wcscpy_s(exe_path, MAX_PATH, me.szExePath);

	rc = false;
	while (Module32Next(snapshot, &me)) {
		if (_wcsicmp(me.szModule, basename))
			continue;

		if (!_wcsicmp(me.szExePath, module)) {
			if (!pids.count(pe->th32ProcessID)) {
				printf("%d: 3DMigoto loaded :)\n", pe->th32ProcessID);
				pids.insert(pe->th32ProcessID);
			}
			rc = true;
		}
		else {
			wcscpy_s(mod_path, MAX_PATH, me.szExePath);
			wcsrchr(exe_path, L'\\')[1] = '\0';
			wcsrchr(mod_path, L'\\')[1] = '\0';
			if (!_wcsicmp(exe_path, mod_path)) {
				printf("\n\n\n"
					"WARNING: Found a second copy of 3DMigoto loaded from the game directory:\n"
					"%S\n"
					"This may crash - please remove the copy in the game directory and try again\n\n\n",
					me.szExePath);
				wait_exit(EXIT_FAILURE);
			}
		}
	}

out_close:
	CloseHandle(snapshot);
	return rc;
}

static bool check_for_running_target(wchar_t* target, const wchar_t* module)
{
	// https://docs.microsoft.com/en-us/windows/desktop/ToolHelp/taking-a-snapshot-and-viewing-processes
	HANDLE snapshot;
	PROCESSENTRY32 pe;
	bool rc = false;
	wchar_t* basename = wcsrchr(target, '\\');
	static std::set<DWORD> pids;

	if (basename)
		basename++;
	else
		basename = target;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("Unable to verify if 3DMigoto was successfully loaded: %d\n", GetLastError());
		return false;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(snapshot, &pe)) {
		printf("Unable to verify if 3DMigoto was successfully loaded: %d\n", GetLastError());
		goto out_close;
	}

	do {
		if (_wcsicmp(pe.szExeFile, basename))
			continue;

		rc = verify_injection(&pe, module, !pids.count(pe.th32ProcessID)) || rc;
		pids.insert(pe.th32ProcessID);
	} while (Process32Next(snapshot, &pe));

out_close:
	CloseHandle(snapshot);
	return rc;
}

static void wait_for_target(const char* target_a, const wchar_t* module_path, bool wait, int delay, bool launched)
{
	wchar_t target_w[MAX_PATH];

	if (!MultiByteToWideChar(CP_UTF8, 0, target_a, -1, target_w, MAX_PATH))
		return;

	int check_count = 0;
	for (int seconds = 0; wait || delay == -1; seconds++) {


		bool check_result = check_for_running_target(target_w, module_path);
		check_count += 1;
		if (check_count > 5) {
			break;
		}

		if (check_result && delay != -1) {
			break;
		}
		Sleep(1000);

		if (launched && seconds == 3) {
			printf("\nStill waiting for the game to start...\n"
				"If the game does not launch automatically, leave this window open and run it manually.\n"
				"You can also adjust/remove the [Loader] launch= option in the d3dx.ini as desired.\n\n");
		}
	}

	for (int i = delay; i > 0; i--) {
		printf("Shutting down loader in %i...\r", i);
		Sleep(1000);
		check_for_running_target(target_w, module_path);
	}
	printf("\n");
}

static void elevate_privileges()
{
	DWORD size = sizeof(TOKEN_ELEVATION);
	TOKEN_ELEVATION Elevation;
	wchar_t path[MAX_PATH];
	HANDLE token = NULL;
	int rc;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		return;

	if (!GetTokenInformation(token, TokenElevation, &Elevation, sizeof(Elevation), &size)) {
		CloseHandle(token);
		return;
	}

	CloseHandle(token);

	if (Elevation.TokenIsElevated)
		return;

	if (!GetModuleFileName(NULL, path, MAX_PATH))
		return;

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	rc = (int)(uintptr_t)ShellExecute(NULL, L"runas", path, NULL, NULL, SW_SHOWNORMAL);
	if (rc > 32) // Success
		exit(0);
	if (rc == SE_ERR_ACCESSDENIED)
		wait_exit(EXIT_FAILURE, _strdup("Unable to run as admin: Access Denied\n"));
	printf("Unable to run as admin: %d\n", rc);
	wait_exit(EXIT_FAILURE);
}

wchar_t* deduce_working_directory(wchar_t* setting, wchar_t dir[MAX_PATH])
{
	DWORD ret;
	wchar_t* file_part = NULL;

	ret = GetFullPathName(setting, MAX_PATH, dir, &file_part);
	if (!ret || ret >= MAX_PATH)
		return NULL;

	ret = GetFileAttributes(dir);
	if (ret == INVALID_FILE_ATTRIBUTES)
		return NULL;

	if (!(ret & FILE_ATTRIBUTE_DIRECTORY) && file_part)
		*file_part = '\0';

	printf("Using working directory: \"%S\"\n", dir);

	return dir;
}

int main()
{
	char* buf, target[MAX_PATH], setting[MAX_PATH], module_path[MAX_PATH];
	wchar_t setting_w[MAX_PATH], working_dir[MAX_PATH], * working_dir_p = NULL;
	DWORD filesize, readsize;
	const char* ini_section;
	wchar_t module_full_path[MAX_PATH];
	int rc = EXIT_FAILURE;
	HANDLE ini_file;
	HMODULE module;
	int hook_proc;
	FARPROC fn;
	HHOOK hook;
	bool launch;

	CreateMutexA(0, FALSE, "Local\\3DMigoto-Knife");
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		wait_exit(EXIT_FAILURE, _strdup("ERROR: Another instance of the 3DMigoto Loader is already running. Please close it and try again\n"));

	printf("\n------------------------------- 3DMigoto Knife ------------------------------\n\n");

	ini_file = CreateFile(L"d3dx.ini", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (ini_file == INVALID_HANDLE_VALUE)
		exit_usage("Unable to open d3dx.ini\n");

	filesize = GetFileSize(ini_file, NULL);
	buf = new char[filesize + 1];
	if (!buf)
		wait_exit(EXIT_FAILURE, _strdup("Unable to allocate d3dx.ini buffer\n"));

	if (!ReadFile(ini_file, buf, filesize, &readsize, 0) || filesize != readsize)
		wait_exit(EXIT_FAILURE, _strdup("Error reading d3dx.ini\n"));

	CloseHandle(ini_file);

	ini_section = find_ini_section_lite(buf, "loader");
	if (!ini_section)
		exit_usage("d3dx.ini missing required [Loader] section\n");

	// Check that the target is configured. We don't do anything with this
	// setting from here other than to make sure it is set, because the
	// injection method we are using cannot single out a specific process.
	// Once 3DMigoto has been injected it into a process it will check this
	// value and bail if it is in the wrong one.
	if (!find_ini_setting_lite(ini_section, "target", target, MAX_PATH))
		exit_usage("d3dx.ini [Loader] section missing required \"target\" setting\n");
	
	
	

	if (!find_ini_setting_lite(ini_section, "module", module_path, MAX_PATH))
		exit_usage("d3dx.ini [Loader] section missing required \"module\" setting\n");

	//we always need admin privileges.
	elevate_privileges();

	module = LoadLibraryA(module_path);
	if (!module) {
		printf("Unable to load 3DMigoto \"%s\"\n", module_path);
		wait_exit(EXIT_FAILURE);
	}

	GetModuleFileName(module, module_full_path, MAX_PATH);
	printf("Loaded %S\n\n", module_full_path);

	//ǿ��ʹ��CBTProc
	fn = GetProcAddress(module, "CBTProc");

	if (!fn) {
		wait_exit(EXIT_FAILURE, _strdup("Module does not support injection method\n"
			"Make sure this is a recent 3DMigoto d3d11.dll\n"));
	}

	//hook_proc = find_ini_int_lite(ini_section, "hook_proc", WH_CBT);

	hook_proc = WH_CBT;
	hook = SetWindowsHookEx(hook_proc, (HOOKPROC)fn, module, 0);
	if (!hook)
		wait_exit(EXIT_FAILURE, _strdup("Error installing hook\n"));

	rc = EXIT_SUCCESS;

	printf("3DMigoto ready - Now run the game.\n");

	//uncomment this to always inject to specific processs without reading d3dx.ini
	//char target_str[] = "C:\\Program Files\\Star Rail\\Game\\StarRail.exe";
	
	//Here we always set delay to 5
	// means it will automatically quit when arrived 5 seconds don't care if it's success inject.
	wait_for_target(target, module_full_path,
		true,
		5, false);

	UnhookWindowsHookEx(hook);
	delete[] buf;
	
	//usually we don't need to pause.
	//system("pause");

	return rc;
}




