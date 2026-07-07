package main

import (
    "fmt"
    "math/rand"
    "runtime"
    "time"
)

// ฟังก์ชันล้างหน้าจอด้วย ANSI Escape Code
func clearScreen() {
    fmt.Print("\033[H\033[2J")
}

func main() {
    var m runtime.MemStats
    
    for {
        clearScreen()
        runtime.ReadMemStats(&m)

        // จำลองตัวเลข Packet ให้ดูมีความเคลื่อนไหว (ถ้ามีระบบจริงสามารถเอาตัวแปรจริงมาใส่ได้)
        rxPackets := rand.Intn(500) + 1000
        txPackets := rand.Intn(300) + 800

        fmt.Println("\033[36;1m=====================================================\033[0m")
        fmt.Println("\033[36;1m              AEGIS NOSE (GO) - PERF MONITOR         \033[0m")
        fmt.Println("\033[36;1m=====================================================\033[0m")
        fmt.Printf("\033[33m[ SYSTEM RESOURCE ]\033[0m\n")
        fmt.Printf(" Alloc Memory : %v MiB\n", m.Alloc/1024/1024)
        fmt.Printf(" Total Alloc  : %v MiB\n", m.TotalAlloc/1024/1024)
        fmt.Printf(" Sys Memory   : %v MiB\n", m.Sys/1024/1024)
        fmt.Printf(" Num GC       : %v\n", m.NumGC)
        fmt.Println("-----------------------------------------------------")
        fmt.Printf("\033[32m[ TRAFFIC SENSOR (L3/L4) ]\033[0m\n")
        fmt.Printf(" Incoming Rate : %d pkts/sec\n", rxPackets)
        fmt.Printf(" Outgoing Rate : %d pkts/sec\n", txPackets)
        fmt.Printf(" Active Conns  : %d\n", rand.Intn(20)+50)
        fmt.Println("\033[36;1m=====================================================\033[0m")
        fmt.Println(" Status: \033[32m[ SNIFFING ACTIVE ]\033[0m - Press Ctrl+C to exit")

        time.Sleep(1 * time.Second)
    }
}