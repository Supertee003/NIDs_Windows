use std::fs::File;
use std::io::{BufRead, BufReader};
 use std::thread;
 use std::time::Duration;

// ====== ANSI Colors ======
const C_RESET: &str = "\x1b[0m";
const C_RED: &str = "\x1b[91;1m";
const C_ORANGE: &str = "\x1b[38;5;208m";
const C_YELLOW: &str = "\x1b[93m";
const C_GREEN: &str = "\x1b[92m";
const C_CYAN: &str = "\x1b[96;1m";
const C_MAGENTA: &str = "\x1b[95;1m";
const C_DIM: &str = "\x1b[2m";

 fn clear_screen() {
     print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
 }

// ====== DEFCON Configuration (5 levels, matching Go Goroutines logic) ======
// DEFCON 5 = SAFE      (0 alerts)
// DEFCON 4 = ELEVATED  (1-5 alerts)
// DEFCON 3 = HIGH      (5+ alerts or 1+ critical)
// DEFCON 2 = SEVERE    (5+ critical or 3+ blocks)
// DEFCON 1 = MAXIMUM   (10+ critical or 5+ blocks or kernel threats)

struct DefconInfo {
    level: u8,
    label: &'static str,
    color: &'static str,
    description: &'static str,
}

fn calculate_defcon(total: usize, critical: usize, blocked: usize, kernel: usize) -> DefconInfo {
    if critical >= 10 || blocked >= 5 || kernel >= 3 {
        DefconInfo { level: 1, label: "MAXIMUM", color: C_MAGENTA,
            description: "10+ critical or 5+ blocks or kernel threats" }
    } else if critical >= 5 || blocked >= 3 {
        DefconInfo { level: 2, label: "SEVERE", color: C_RED,
            description: "5+ critical or 3+ blocked IPs" }
    } else if total >= 5 || critical >= 1 {
        DefconInfo { level: 3, label: "HIGH", color: C_ORANGE,
            description: "5+ alerts or 1+ critical" }
    } else if total >= 1 {
        DefconInfo { level: 4, label: "ELEVATED", color: C_YELLOW,
            description: "1-5 alerts detected" }
    } else {
        DefconInfo { level: 5, label: "SAFE", color: C_GREEN,
            description: "0 alerts — Normal operations" }
    }
}

 fn main() {
     let log_path = "logs/anomalous.json";

     loop {
         clear_screen();

        println!("{C_CYAN}====================================================={C_RESET}");
        println!("{C_CYAN}         AEGIS MOUTH (RUST) — DEFCON SECURITY MONITOR{C_RESET}");
        println!("{C_CYAN}====================================================={C_RESET}");

        let mut total_alerts: usize = 0;
        let mut critical_count: usize = 0;
        let mut blocked_count: usize = 0;
        let mut kernel_count: usize = 0;
         let mut last_threat = String::from("None");

         if let Ok(file) = File::open(log_path) {
             let reader = BufReader::new(file);
             for line in reader.lines() {
                 if let Ok(content) = line {
                    if content.trim().is_empty() { continue; }
                    total_alerts += 1;
                    last_threat = content.clone();

                    // Parse severity, policy, tier from JSON (simple string matching)
                    if content.contains("\"Critical\"") { critical_count += 1; }
                    if content.contains("\"Drop\"") || content.contains("\"Block\"") || content.contains("\"BLOCK\"") { blocked_count += 1; }
                    if content.contains("\"Tier-3\"") || content.contains("\"KERNEL_FILE\"") || content.contains("\"KERNEL_PROCESS\"") { kernel_count += 1; }
                 }
             }
         }

        let defcon = calculate_defcon(total_alerts, critical_count, blocked_count, kernel_count);

        // ====== DEFCON Display ======
        println!("{color}[ DEFCON {level}: {label} ]{C_RESET}", color=defcon.color, level=defcon.level, label=defcon.label);
        println!("{C_DIM}  {desc}{C_RESET}", desc=defcon.description);
        println!("  Alerts: {total} | Critical: {C_RED}{crit}{C_RESET} | Blocked: {blk} | Kernel: {kern}",
            total=total_alerts, crit=critical_count, blk=blocked_count, kern=kernel_count);
         println!("-----------------------------------------------------");

        // ====== DEFCON Bar ======
        print!("  ");
        for i in 1..=5 {
            if i >= defcon.level {
                print!("{color}██{C_RESET} ", color=defcon.color);
            } else {
                print!("{C_DIM}  {C_RESET} ");
            }
        }
        println!("\n  1  2  3  4  5");
        println!("-----------------------------------------------------");

        // ====== Statistics ======
        println!("{C_CYAN}[ STATISTICS ]{C_RESET}");
        println!(" Total Threats    : {C_RED}{total}{C_RESET}", total=total_alerts);
        println!(" Critical Threats : {C_RED}{crit}{C_RESET}", crit=critical_count);
        println!(" Blocked/Dropped  : {C_YELLOW}{blk}{C_RESET}", blk=blocked_count);
        println!(" Kernel Events    : {C_ORANGE}{kern}{C_RESET}", kern=kernel_count);
        println!("-----------------------------------------------------");

        // ====== Last Threat ======
        println!("{C_CYAN}[ LAST INTERCEPTED THREAT ]{C_RESET}");
        if total_alerts > 0 {
            let display = if last_threat.len() > 80 {
                format!("{}...", &last_threat[0..77])
             } else {
                 last_threat
             };
            println!(" {C_YELLOW}>> {display}{C_RESET}");
         } else {
            println!(" {C_DIM}>> Waiting for anomalous packets...{C_RESET}");
         }

        println!("{C_CYAN}====================================================={C_RESET}");
        println!(" Status: {C_GREEN}[ READY TO ENFORCE ]{C_RESET} | Auto-refresh 1s");
        println!(" Architecture: Zig Core + Python Brain + Rust Shield + Go Nose + C++ Drivers");

         thread::sleep(Duration::from_secs(1));
     }
}

            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(content) = line {
                    if content.trim().is_empty() { continue; }
                    total_alerts += 1;
                    last_threat = content.clone();

                    // Parse severity, policy, tier from JSON (simple string matching)
                    if content.contains("\"Critical\"") { critical_count += 1; }
                    if content.contains("\"Drop\"") || content.contains("\"Block\"") || content.contains("\"BLOCK\"") { blocked_count += 1; }
                    if content.contains("\"Tier-3\"") || content.contains("\"KERNEL_FILE\"") || content.contains("\"KERNEL_PROCESS\"") { kernel_count += 1; }
                }
            }
        }

        let defcon = calculate_defcon(total_alerts, critical_count, blocked_count, kernel_count);

        // ====== DEFCON Display ======
        println!("{color}[ DEFCON {level}: {label} ]{C_RESET}", color=defcon.color, level=defcon.level, label=defcon.label);
        println!("{C_DIM}  {desc}{C_RESET}", desc=defcon.description);
        println!("  Alerts: {total} | Critical: {C_RED}{crit}{C_RESET} | Blocked: {blk} | Kernel: {kern}",
            total=total_alerts, crit=critical_count, blk=blocked_count, kern=kernel_count);
        println!("-----------------------------------------------------");

        // ====== DEFCON Bar ======
        print!("  ");
        for i in 1..=5 {
            if i >= defcon.level {
                print!("{color}██{C_RESET} ", color=defcon.color);
            } else {
                print!("{C_DIM}  {C_RESET} ");
            }
        }
        println!("\n  1  2  3  4  5");
        println!("-----------------------------------------------------");

        // ====== Statistics ======
        println!("{C_CYAN}[ STATISTICS ]{C_RESET}");
        println!(" Total Threats    : {C_RED}{total}{C_RESET}", total=total_alerts);
        println!(" Critical Threats : {C_RED}{crit}{C_RESET}", crit=critical_count);
        println!(" Blocked/Dropped  : {C_YELLOW}{blk}{C_RESET}", blk=blocked_count);
        println!(" Kernel Events    : {C_ORANGE}{kern}{C_RESET}", kern=kernel_count);
        println!("-----------------------------------------------------");

        // ====== Last Threat ======
        println!("{C_CYAN}[ LAST INTERCEPTED THREAT ]{C_RESET}");
        if total_alerts > 0 {
            let display = if last_threat.len() > 80 {
                format!("{}...", &last_threat[0..77])
            } else {
                last_threat
            };
            println!(" {C_YELLOW}>> {display}{C_RESET}");
        } else {
            println!(" {C_DIM}>> Waiting for anomalous packets...{C_RESET}");
        }

        println!("{C_CYAN}====================================================={C_RESET}");
        println!(" Status: {C_GREEN}[ READY TO ENFORCE ]{C_RESET} | Auto-refresh 1s");
        println!(" Architecture: Zig Core + Python Brain + Rust Shield + Go Nose + C++ Drivers");

        thread::sleep(Duration::from_secs(1));
    }
}
