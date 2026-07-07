// [wfp_interceptor.c] - WFP Callout Driver (Kernel Mode)
#include <fwpsk.h>
#include <fwpmk.h>

// ฟังก์ชันคอลแบ็กหลักที่ WFP จะเรียกเมื่อมีแพ็กเก็ตวิ่งผ่าน
void NTAPI AegisClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut) 
{
    // 1. ตรวจสอบระดับ IRQL (ต้องจัดการอย่างระมัดระวัง)
    KIRQL currentIrql = KeGetCurrentIrql();

    // 2. ดึงข้อมูลดิบ (Raw Packet) จาก NET_BUFFER_LIST
    PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)layerData;
    if (nbl == NULL) return;

    // 3. จองหน่วยความจำแบบ Non-Paged Pool (ไม่ถูกย้ายลง Paging File แน่นอน)
    // เพื่อให้พร้อมสำหรับการส่งต่อข้อมูลโดยไม่เกิด Page Fault ที่ IRQL สูง
    ULONG dataLength = ...; // คำนวณขนาดแพ็กเก็ต
    PVOID secureBuffer = ExAllocatePoolWithTag(NonPagedPool, dataLength, 'AEGS');

    if (secureBuffer != NULL) {
        // คัดลอกข้อมูลลง Secure Buffer
        // ... (Copy NBL data to secureBuffer) ...

        // 4. ส่งข้อมูลเข้าสู่ Named Pipe หรือ IOCTL เพื่อให้ User-Mode (Zig) รับไปประมวลผลต่อ
        SendToUserModePipe(secureBuffer, dataLength);

        // คืนหน่วยความจำเมื่อส่งเสร็จ
        ExFreePoolWithTag(secureBuffer, 'AEGS');
    }

    // กำหนดค่า Default Action (ปล่อยผ่านไปก่อน ให้ Zig เป็นตัวสั่ง Drop ทีหลัง - Out-of-band inspection)
    classifyOut->actionType = FWP_ACTION_PERMIT;
}