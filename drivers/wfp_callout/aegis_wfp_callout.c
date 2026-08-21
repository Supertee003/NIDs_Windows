/* aegis_wfp_callout.c - WFP callout registration and callbacks */

#include "aegis_wfp.h"

static UINT32 g_CalloutId = 0;

/* Classify callback - pass-through */
void
AegisWfpClassifyFn(
    IN const FWPS_INCOMING_VALUES0         *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                              *layerData,
    IN const void                           *classifyContext,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut
)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    classifyOut->actionType = FWP_ACTION_PERMIT;
}

/* Notify callback */
NTSTATUS
AegisWfpNotifyFn(
    IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID              *filterKey,
    IN const FWPS_FILTER0      *filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

/* Register the callout with WFP */
NTSTATUS
AegisWfpRegisterCallouts(
    PDEVICE_OBJECT DeviceObject
)
{
    NTSTATUS     status;
    FWPS_CALLOUT0 callout;

    RtlZeroMemory(&callout, sizeof(FWPS_CALLOUT0));

    callout.calloutKey    = AEGIS_CALLOUT_KEY;
    callout.classifyFn    = AegisWfpClassifyFn;
    callout.notifyFn      = AegisWfpNotifyFn;
    callout.flowDeleteFn  = NULL;

    status = FwpsCalloutRegister0(DeviceObject, &callout, &g_CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("AegisWfp: FwpsCalloutRegister0 failed 0x%08lX\n", status);
        return status;
    }

    DbgPrint("AegisWfp: callout registered, id=%u\n", g_CalloutId);
    return STATUS_SUCCESS;
}

/* Unregister the callout */
VOID
AegisWfpUnregisterCallouts(VOID)
{
    if (g_CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_CalloutId);
        DbgPrint("AegisWfp: callout unregistered, id=%u\n", g_CalloutId);
        g_CalloutId = 0;
    }
}