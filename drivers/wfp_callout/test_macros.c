#define INITGUID
#include <guiddef.h>
#include <ntddk.h>
#include "wfp_kernel_compat.h"

/* Check what winapifamily.h actually defines */
#ifndef WINAPI_FAMILY
#pragma message("WINAPI_FAMILY: NOT DEFINED after ntddk.h")
#else
#pragma message("WINAPI_FAMILY: DEFINED")
#endif

#ifndef WINAPI_FAMILY_PARTITION
#pragma message("WINAPI_FAMILY_PARTITION: NOT DEFINED after ntddk.h")
#else
/* Test the macro expansion */
#if WINAPI_FAMILY_PARTITION(1)
#pragma message("WINAPI_FAMILY_PARTITION(1): TRUE")
#else
#pragma message("WINAPI_FAMILY_PARTITION(1): FALSE")
#endif
#endif

#ifndef WINAPI_PARTITION_DESKTOP
#pragma message("WINAPI_PARTITION_DESKTOP: NOT DEFINED")
#else
#pragma message("WINAPI_PARTITION_DESKTOP: DEFINED")
#endif

/* Now include fwptypes.h and check if types appear */
#include <fwptypes.h>

#ifdef FWP_VALUE0
#pragma message("FWP_VALUE0: DEFINED after fwptypes.h")
#else
#pragma message("FWP_VALUE0: NOT DEFINED after fwptypes.h")
#endif

#ifdef FWP_CONDITION_VALUE0
#pragma message("FWP_CONDITION_VALUE0: DEFINED")
#else
#pragma message("FWP_CONDITION_VALUE0: NOT DEFINED")
#endif

#ifdef FWP_MATCH_TYPE
#pragma message("FWP_MATCH_TYPE: DEFINED")
#else
#pragma message("FWP_MATCH_TYPE: NOT DEFINED")
#endif

#ifdef FWP_ACTION_TYPE
#pragma message("FWP_ACTION_TYPE: DEFINED")
#else
#pragma message("FWP_ACTION_TYPE: NOT DEFINED")
#endif

/* Also check __fwpstypes_h__ guard */
#ifndef __fwpstypes_h__
#pragma message("__fwpstypes_h__: NOT DEFINED (fwpstypes.h not included yet)")
#else
#pragma message("__fwpstypes_h__: DEFINED (fwpstypes.h was already included)")
#endif
