"""sensor_pipe.pyx — T2-BRAIN-023b Cython named-pipe sender for Tier-2 findings.

Standing rule: Python talks to OS C APIs through Cython, never ctypes as
the primary path. This module wraps kernel32 CreateFileW/WriteFile/
CloseHandle so the brain's sensor-pipe return contract
(`brain/windows_brain.py::send_to_sensor_pipe`) crosses into C here.

Contract (mirrors the ctypes fallback byte-for-byte):
  - send_bytes(pipe_name, data) -> "SENT" | "FAILED"
  - FAILED on open failure, short/failed write. Never raises for
    transport conditions; FAILED is an operator-visible transport
    failure, never a detection claim.
  - No policy/PEP/firewall/WFP surface: raw byte transport only.

Build: `cd brain/cython && python setup.py build_ext --inplace`
(kernel32 is default-linked on Windows; no extra link args).
If the .pyd is absent, windows_brain falls back to the ctypes sender.
"""

cdef extern from "windows.h":
    ctypedef void* HANDLE
    ctypedef unsigned long DWORD
    ctypedef int BOOL
    # NOTE: CreateFileA (not W) — the sensor pipe name is a fixed ASCII
    # constant, so the ANSI entry point reaches the identical pipe object
    # with no wide-string plumbing in Cython (which has no wchar_t type).
    HANDLE CreateFileA(const char* lpFileName, DWORD dwDesiredAccess,
        DWORD dwShareMode, void* lpSecurityAttributes,
        DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile)
    BOOL WriteFile(HANDLE hFile, const void* lpBuffer,
        DWORD nNumberOfBytesToWrite, DWORD* lpNumberOfBytesWritten,
        void* lpOverlapped)
    BOOL CloseHandle(HANDLE hObject)

cdef DWORD GENERIC_READ_WRITE = 0xC0000000  # GENERIC_READ | GENERIC_WRITE
cdef DWORD OPEN_EXISTING = 3


def send_bytes(str pipe_name, bytes data):
    """Write data to a Windows named pipe. Returns "SENT" or "FAILED"."""
    cdef bytes name_b = pipe_name.encode("ascii")
    cdef const char* name_c = name_b
    cdef HANDLE handle = CreateFileA(
        name_c, GENERIC_READ_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)
    if handle == <HANDLE>-1:
        return "FAILED"
    cdef DWORD written = 0
    cdef const char* buf = data
    cdef DWORD want = <DWORD>len(data)
    try:
        if not WriteFile(handle, buf, want, &written, NULL):
            return "FAILED"
        if written != want:
            return "FAILED"
        return "SENT"
    finally:
        CloseHandle(handle)
