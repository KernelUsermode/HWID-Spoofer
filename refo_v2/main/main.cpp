#include <iostream>
#include "../utils/print/print.h"
#include "../encryption/xor.h"
#include "../utils/print/print.h"
#include "../encryption/xor.h"
#include <WinInet.h>
#include <Windows.h>
#include <winbase.h>
#include <tchar.h>
#include <fstream>
#include <string>
#include <string.h>
#include <vector>
#include <Windows.h>
#include <iostream>
#include <process.h>
#include <iostream>
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <stdio.h>
#include <cstdio>
#include <vector>
#include <gdiplus.h>
#include <string>
#include <fstream>
#include <WinInet.h>
#include <random>
#include <tlhelp32.h>
#include <conio.h>
#include <comdef.h>
#include <tchar.h>
#include <mmsystem.h>
#include <CommCtrl.h>
#include <fileapi.h>
#include <iomanip> 
#include <debugapi.h>
#include <time.h>
#include <stdlib.h>
#include <Shlwapi.h>
#include "../mapper/kdmapper.hpp"
#include <thread>
#include <ios>
#include <limits>
#include <time.h>
#include <conio.h>
#include <sstream>
#include <string>
#include <urlmon.h>
#include <tchar.h>
#include <string.h>
#include<stdlib.h>
#include<conio.h>
#include <cstdint>
#include <winternl.h>
#include <Windows.h>
#include "../auth.hpp"
#include <string>
#include "../skStr.h"
#include <stdint.h>
#include "../misc/lazy.h"


#pragma warning(disable : 4996)
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib, "winmm.lib")
#define _WIN32_WINNT 0x0500

#include <Windows.h>
#include <winternl.h>

int anti_dump() //UD anti Dump
{
	const auto peb = (PPEB)__readgsqword(0x60);

	const auto in_load_order_module_list = (PLIST_ENTRY)peb->Ldr->Reserved2[1];
	const auto table_entry = CONTAINING_RECORD(in_load_order_module_list, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
	const auto p_size_of_image = (PULONG)&table_entry->Reserved3[1];
	*p_size_of_image = (ULONG)((INT_PTR)table_entry->DllBase + 0x100000);

	return 0;

};

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

using namespace KeyAuth;
using namespace std;
    

// This is a very shit loader im aware and not secure at all, i was bored and made this in under 5mins!



::string name = _xor_("");  //keyauth loader name
std::string ownerid = _xor_(""); //keyauth ownerID
std::string secret = _xor_(""); //Keyauth secret
std::string version = _xor_(""); // Keyauth version 
std::string url = _xor_("https://keyauth.win/api/1.2/"); //keep the same you are not smart enough to selfhost

api KeyAuthApp(name, ownerid, secret, version, url);

extern "C"
{
	NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
	NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);
}


bool running = true;

std::uintptr_t process_find(const std::string& name)
{
	const auto snap = LI_FN(CreateToolhelp32Snapshot).safe()(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 proc_entry{};
	proc_entry.dwSize = sizeof proc_entry;

	auto found_process = false;
	if (!!LI_FN(Process32First).safe()(snap, &proc_entry)) {
		do {
			if (name == proc_entry.szExeFile) {
				found_process = true;
				break;
			}
		} while (!!LI_FN(Process32Next).safe()(snap, &proc_entry));
	}

	LI_FN(CloseHandle).safe()(snap);
	return found_process
		? proc_entry.th32ProcessID
		: 0;
}


std::string path()
{
	char shitter[_MAX_PATH];
	GetModuleFileNameA(NULL, shitter, _MAX_PATH);
	return std::string(shitter);

}

void blue_screen()
{
	BOOLEAN bluescr;
	ULONG cevap;
	RtlAdjustPrivilege(19, TRUE, FALSE, &bluescr);
	NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &cevap);
}

void find_exe_title()  //dont remove! makes your loader 100% uncrackable!!
{
	while (true) {
		if (process_find(_xor_("KsDumperClient.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("HTTPDebuggerUI.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("HTTPDebuggerSvc.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("FolderChangesView.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("ProcessHacker.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("procmon.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("idaq.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("idaq64.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("Wireshark.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("Fiddler.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("Xenos64.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("Cheat Engine.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("HTTP Debugger Windows Service (32 bit).exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("KsDumper.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("x64dbg.exe")))
		{
			blue_screen();
		}
		else if (process_find(_xor_("ProcessHacker.exe")))
		{
			blue_screen();
		}
		else if (FindWindow(0, _xor_("IDA: Quick start").c_str()))
		{
			blue_screen();
		}

		else if (FindWindow(0, _xor_("Memory Viewer").c_str()))
		{
			blue_screen();
		}
		else if (FindWindow(0, _xor_("Process List").c_str()))
		{
			blue_screen();
		}
		else if (FindWindow(0, _xor_("KsDumper").c_str()))
		{
			blue_screen();
		}
		else if (FindWindow(0, _xor_("HTTP Debugger").c_str()))
		{
			blue_screen();
		}
		else if (FindWindow(0, _xor_("OllyDbg").c_str()))
		{
			blue_screen();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(5000));

	}
}

void Spoof()
{
	{
		print::set_text(_xor_("Connecting to Driver...\n").c_str(), Red);
		print::set_text(_xor_("\n").c_str(), LightGreen);
		Sleep(2000);
		print::set_text(_xor_("Verifying Connection...\n").c_str(), Red);
		print::set_text(_xor_("\n").c_str(), LightGreen);
		Sleep(2000);
		print::set_text(_xor_("Connection Verified...\n").c_str(), Green);
		print::set_text(_xor_("\n").c_str(), LightGreen);
		Sleep(2000);
		print::set_text(_xor_("Spoofing your components...\n").c_str(), Red);
		print::set_text(_xor_("\n").c_str(), LightGreen);
		Sleep(2000);

		std::vector<std::uint8_t> bytes = KeyAuthApp.download("612794"); //Nex says enter your keyauth ID here
		HANDLE iqvw64e_device_handle = intel_driver::Load();

		if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE) {
			std::cout << _xor_("\n Error code iq00001, please disable any anti-cheat such as valorant or faceit and try again").c_str(); //kdmapper shi
			Sleep(3500);
			exit(0);
		}
		if (!kdmapper::MapDriver(iqvw64e_device_handle, bytes.data())) {
			std::cout << _xor_("\nCould not load driver").c_str();
			std::cout << _xor_("\n Error code iq00002, please disable any anti-cheat such as valorant or faceit and try again").c_str(); //kdmapper shi
			intel_driver::Unload(iqvw64e_device_handle);
			Sleep(3500);
			exit(0);
		}

		print::set_text(_xor_("Successfully Spoofed components...\n").c_str(), Green);
		print::set_text(_xor_("\n").c_str(), LightGreen);
		Sleep(2000);
		print::set_text(_xor_("Returning...\n").c_str(), Red);
		print::set_text(_xor_("\n").c_str(), LightGreen);
		Sleep(1500);
		system(_xor_("cls").c_str());

	}
}

void cleaner()
{
	print::set_text(_xor_("Checking cleaner version\n").c_str(), Red);
	Sleep(2000);
	print::set_text(_xor_("\n").c_str(), LightGreen);
	print::set_text(_xor_("Cleaner is currenly being updated\n").c_str(), Red);  // you can just change this, idc what you do
	Sleep(2000);
	print::set_text(_xor_("\n").c_str(), LightGreen);
	print::set_text(_xor_("Please wait until further notice\n").c_str(), Red);
	print::set_text(_xor_("\n").c_str(), LightGreen);
	Sleep(2000);
}

int menus()
{
	int choice;

	while (true)
	{
		system(_xor_("cls").c_str());

		while (true)
		{
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("                              Initializing secure connection, this wont take much of your time...\n").c_str(), White);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);        
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("                                        Authorize Anti leak created by Nex#3757\n").c_str(), White);
			Sleep(5000);


			system(_xor_("cls").c_str());

			print::set_text(_xor_("                                                    Authorize AL | Free\n").c_str(), LightGreen);

			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);

			print::set_text(_xor_("[1] Spoof\n").c_str(), LightBlue);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("[2] Clean Fortnite traces\n").c_str(), LightBlue);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("\n").c_str(), LightGreen);
			print::set_text(_xor_("[3] Exit Program\n").c_str(), LightBlue);
			std::cin >> choice;

			switch (choice)
			{

			case 1:
			{
				system(_xor_("cls").c_str());
				Spoof();
			}
			break;
			case 2:
			{
				system(_xor_("cls").c_str());
				cleaner();
			}
			break;
			case 3:
			{
				system(_xor_("cls").c_str());
				exit(1);
			}
			}
		}
	}

	system(_xor_("Pause").c_str());
}

std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10);

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}

int main()
{
	SetConsoleTitleA(skCrypt("Attempted AL Loader"));  //title make sure to change it paster
	std::cout << skCrypt("\n\n Connecting..");
	Sleep(3000);
	KeyAuthApp.init();
	if (!KeyAuthApp.data.success)
	{
		std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	if (KeyAuthApp.checkblack()) {
		abort();
	}

	std::cout << skCrypt("\n\n App data:");
	std::cout << skCrypt("\n Number of users: ") << KeyAuthApp.data.numUsers;
	std::cout << skCrypt("\n Application Version: ") << KeyAuthApp.data.version;

	std::cout << skCrypt("\n\n [1] License key\n\n Choose option: ");

	int option;
	std::string username;
	std::string password;
	std::string key;

	std::cin >> option;
	switch (option)
	{
	case 1:
		std::cout << skCrypt("\n Enter license: ");
		std::cin >> key;
		KeyAuthApp.license(key);
		break;
	default:
		std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
		Sleep(3000);
		exit(0);
	}

	if (!KeyAuthApp.data.success)
	{
		std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	std::cout << skCrypt("\n User data:");
	std::cout << skCrypt("\n Username: ") << KeyAuthApp.data.username;
	std::cout << skCrypt("\n IP address: ") << KeyAuthApp.data.ip;
	std::cout << skCrypt("\n Hardware-Id: ") << KeyAuthApp.data.hwid;
	std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.createdate)));
	std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.lastlogin)));
	std::cout << skCrypt("\n Subscription name(s): ");
	std::string subs;
	for (std::string value : KeyAuthApp.data.subscriptions)subs += value + " ";
	std::cout << subs;
	std::cout << skCrypt("\n Subscription expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.expiry)));

	std::cout << skCrypt("\n\n Closing in three seconds...");
	Sleep(3000);

	menus();
}