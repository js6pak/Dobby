#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHookRouting.h"

PUBLIC int DobbyHook(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func) {
  int result = DobbyPrepare(address, replace_func, origin_func);
  if (result != 0)
    return result;
  return DobbyCommit(address);
}

PUBLIC int DobbyPrepare(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func) {
  if (!address) {
    ERROR_LOG("function address is 0x0");
    return RS_FAILED;
  }

#if defined(__APPLE__) && defined(__arm64__)
#if __has_feature(ptrauth_calls)
  address = ptrauth_strip(address, ptrauth_key_asia);
  replace_func = ptrauth_strip(replace_func, ptrauth_key_asia);
#endif
#endif

#if defined(ANDROID)
  void *page_align_address = (void *)ALIGN_FLOOR(address, OSMemory::PageSize());
  if (!OSMemory::SetPermission(page_align_address, OSMemory::PageSize(), kReadExecute)) {
    return RS_FAILED;
  }
#endif

  DLOG(0, "----- [DobbyPrepare:%p] -----", address);

  // check if already register
  auto entry = Interceptor::SharedInstance()->find((addr_t)address);
  if (entry) {
    ERROR_LOG("%p already been hooked.", address);
    return RS_FAILED;
  }

  entry = new InterceptEntry(kFunctionInlineHook, (addr_t)address);

  auto *routing = new FunctionInlineHookRouting(entry, replace_func);
  routing->Prepare();
  routing->DispatchRouting();

  // set origin func entry with as relocated instructions
  if (origin_func) {
    *origin_func = (dobby_dummy_func_t)entry->relocated_addr;
  }

  Interceptor::SharedInstance()->add(entry);

  return RS_SUCCESS;
}

PUBLIC int DobbyCommit(void *address) {
  if (!address) {
    ERROR_LOG("function address is 0x0");
    return -1;
  }

  // check if already hooked
  auto entry = Interceptor::SharedInstance()->find((addr_t)address);
  auto route = entry->routing;
  if (entry->is_committed) {
    ERROR_LOG("function %p already been hooked.", address);
    return -1;
  }

  // code patch & hijack original control flow entry
  route->Commit();
  return 0;
}
