#include <stdio.h>

#include <windows.h>

#include "logging/logging.h"
#include "logging/check_logging.h"
#include "PlatformUnifiedInterface/platform.h"

int GetProtectionFromMemoryPermission(MemoryPermission access) {
  if (kReadWriteExecute == access)
    return PAGE_EXECUTE_READWRITE;
  else if (kReadExecute == access)
    return PAGE_EXECUTE_READ;
}

int AllocPageSize() {
  static int lastRet = -1;
  if (lastRet == -1) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    lastRet = si.dwAllocationGranularity; // should be used with VirtualAlloc(MEM_RESERVE)
  }
  return lastRet;
}

int OSMemory::PageSize() {
  static int lastRet = -1;
  if (lastRet == -1) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    lastRet = si.dwPageSize; // should be used with VirtualAlloc(MEM_RESERVE)
  }
  return lastRet;
}

void *OSMemory::Allocate(size_t size, MemoryPermission access) {
  return OSMemory::Allocate(size, access, nullptr);
}

void *OSMemory::Allocate(size_t size, MemoryPermission access, void *fixed_address) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(fixed_address) % AllocPageSize());
  DCHECK_EQ(0, size % PageSize());

  void *result = VirtualAlloc(fixed_address, size, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
  OSMemory::SetPermission(result, size, kReadWriteExecute);
  if (result == nullptr)
    return nullptr;

  // TODO: if need align
  void *aligned_base = result;
  return static_cast<void *>(aligned_base);
}

// static
bool OSMemory::Free(void *address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  return VirtualFree(address, size, MEM_RELEASE);
}

bool OSMemory::Release(void *address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  return OSMemory::Free(address, size);
}

bool OSMemory::SetPermission(void *address, size_t size, MemoryPermission access) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  int prot = GetProtectionFromMemoryPermission(access);

  DWORD oldProtect;
  return VirtualProtect(address, size, prot, &oldProtect);
}

// =====

void OSPrint::Print(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrint(format, args);
  va_end(args);
}

void OSPrint::VPrint(const char *format, va_list args) {
  vprintf(format, args);
}
