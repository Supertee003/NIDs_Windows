@echo off
REM AEGIS NIDS - tshark Packet Capture Helper
REM Captures live packets and saves to PCAP for analysis

set TSHARK="C:\Program Files\Wireshark\tshark.exe"
set OUTPUT_DIR=D:\NIDs_Windows\logs
set PCAP_FILE=%OUTPUT_DIR%\aegis_capture.pcap

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo ============================================
echo   AEGIS NIDS - tshark Packet Capture
echo ============================================
echo.
echo Capturing packets to: %PCAP_FILE%
echo Press Ctrl+C to stop
echo.

REM List available interfaces
echo Available interfaces:
%TSHARK% -D
echo.

REM Capture on first available interface (adjust -i number if needed)
REM -i 1 = first interface, -w = write to file, -b filesize:10240 = 10MB ring buffer
%TSHARK% -i 1 -w "%PCAP_FILE%" -b filesize:10240 -p

echo.
echo Capture stopped. PCAP saved to: %PCAP_FILE%
pause
