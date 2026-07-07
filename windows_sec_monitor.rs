use std::fs::File;
use std::io::{BufRead, BufReader};
use std::thread;
use std::time::Duration;

// ฟังก์ชันล้างหน้าจอด้วย ANSI Escape Code
fn clear_screen() {
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
}

fn main() {
    let log_path = "logs/anomalous.json";

    loop {
        clear_screen();
        
        println!("\x1b[31;1m=====================================================\x1b[0m");
        println!("\x1b[31;1m           AEGIS MOUTH (RUST) - SEC MONITOR          \x1b[0m");
        println!("\x1b[31;1m=====================================================\x1b[0m");

        let mut threat_count = 0;
        let mut last_threat = String::from("None");

        // พยายามอ่านไฟล์ Log เพื่อดึงข้อมูลภัยคุกคาม
        if let Ok(file) = File::open(log_path) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(content) = line {
                    if !content.trim().is_empty() {
                        threat_count += 1;
                        // ดึงข้อความคร่าวๆ มาโชว์ (ในระบบจริงควร parse JSON แต่เราใช้ string match ง่ายๆ ก่อน)
                        last_threat = content; 
                    }
                }
            }
        }

        // ประเมิน DEFCON Level ตามจำนวนภัยคุกคาม
        let (defcon, color) = match threat_count {
            0 => ("DEFCON 5 (SAFE)", "\x1b[32m"),           // เขียว
            1..=10 => ("DEFCON 4 (ELEVATED)", "\x1b[33m"),   // เหลือง
            11..=50 => ("DEFCON 3 (GUARDED)", "\x1b[38;5;208m"), // ส้ม
            _ => ("DEFCON 2 (HIGH RISK)", "\x1b[31;1m"),     // แดง
        };

        println!("\x1b[34m[ SECURITY STATUS ]\x1b[0m");
        println!(" System State  : {}{}\x1b[0m", color, defcon);
        println!(" Total Blocked : \x1b[31;1m{}\x1b[0m events", threat_count);
        println!("-----------------------------------------------------");
        println!("\x1b[34m[ LAST INTERCEPTED THREAT ]\x1b[0m");
        
        if threat_count > 0 {
            // ตัดข้อความให้สั้นลงเพื่อไม่ให้ล้นจอ
            let display_threat = if last_threat.len() > 50 {
                format!("{}...", &last_threat[0..47])
            } else {
                last_threat
            };
            println!(" \x1b[33m>> {}\x1b[0m", display_threat);
        } else {
            println!(" \x1b[90m>> Waiting for anomalous packets...\x1b[0m");
        }

        println!("\x1b[31;1m=====================================================\x1b[0m");
        println!(" Action: \x1b[32m[ READY TO ENFORCE ]\x1b[0m - Auto-refreshing 1s");

        thread::sleep(Duration::from_secs(1));
    }
}