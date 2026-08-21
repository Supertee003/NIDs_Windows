#include <ntddk.h>
#ifdef EXTERN_C_START
#pragma message("YES: EXTERN_C_START is defined after ntddk.h")
#else
#pragma message("NO: EXTERN_C_START is NOT defined after ntddk.h")
#endif
void dummy(void) {}
