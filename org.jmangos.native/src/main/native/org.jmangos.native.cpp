#define UNICODE
#define _UNICODE
#include <tchar.h>
#include "windows.h"
#include <stdio.h>
#include <string>
#include <tlhelp32.h>
#include <shlwapi.h>


extern "C" __declspec(dllexport) BOOL EnableDebugPriv(VOID) {
   HANDLE hToken;
   LUID seDebugNameValue;
   TOKEN_PRIVILEGES tkp;

   if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken )) {
      if(LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &seDebugNameValue )) {
         tkp.PrivilegeCount=1;
         tkp.Privileges[0].Luid = seDebugNameValue;
         tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

         if(AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL )) {
            CloseHandle(hToken);
            return TRUE;
         }
      }
   }

   CloseHandle(hToken);

   return FALSE; 
}

extern "C" __declspec(dllexport) DWORD GetTargetProcessId(LPCWSTR lpProcName) {
   PROCESSENTRY32 pe;
   HANDLE thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   pe.dwSize = sizeof(PROCESSENTRY32);

   if(thSnapshot != INVALID_HANDLE_VALUE) {
      if(Process32First(thSnapshot, &pe)) {
         do {
            if(StrStrI(pe.szExeFile, lpProcName)) {
               CloseHandle(thSnapshot);
               return pe.th32ProcessID;
            }
         } while(Process32Next(thSnapshot, &pe));
      }
      
      CloseHandle(thSnapshot);
   }

   return 0;
}

extern "C" __declspec(dllexport) SIZE_T ReadMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
   SIZE_T numBytesRead;
   if(!ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &numBytesRead)) {
      return 0;
   } else {
      return numBytesRead;
   }
}

extern "C" __declspec(dllexport) SIZE_T WriteMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize) {
   SIZE_T numBytesWritten;
   if(!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &numBytesWritten)) {
      return 0;
   } else {
      return numBytesWritten;
   }
}

