import json
import networkx as nx
from pyvis.network import Network

def generate_threat_graph(log_file="logs/anomalous.json"):
    # 1. สร้าง Graph ว่างๆ ขึ้นมา
    G = nx.Graph()
    
    # โหนดศูนย์กลางคือเซิร์ฟเวอร์ของเรา (NIDS)
    G.add_node("AEGIS_NIDS (Our Server)", color="green", size=30, title="เป้าหมายที่ถูกป้องกัน")

    # 2. อ่านข้อมูลจากไฟล์ Log
    try:
        with open(log_file, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                
                # ดึงข้อมูลการโจมตี
                attack_type = data.get("attack_type", "Unknown")
                
                # สมมติฐาน: ในอนาคตเราจะดึง IP จริงมาได้ (ตอนนี้ใช้ค่า Source ผสมไปก่อนเพื่อจำลอง)
                attacker_node = f"Attacker_{attack_type}" 
                
                # เพิ่มโหนดผู้โจมตี (สีแดง)
                G.add_node(attacker_node, color="red", size=20, title=f"Threat: {attack_type}")
                
                # ลากเส้นเชื่อม (Edge) จากผู้โจมตีมาที่เซิร์ฟเวอร์ของเรา
                G.add_edge(attacker_node, "AEGIS_NIDS (Our Server)", label=attack_type)
                
    except FileNotFoundError:
        print("ยังไม่มีไฟล์ Log ครับ")
        return

    # 3. สร้าง Interactive Graph ด้วย PyVis
    net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white")
    net.from_nx(G)
    
    # บันทึกเป็นไฟล์ HTML
    output_file = "threat_graph.html"
    net.save_graph(output_file)
    print(f"✅ สร้างกราฟสำเร็จ! เปิดไฟล์ {output_file} ใน Web Browser ดูได้เลยครับ")

if __name__ == "__main__":
    generate_threat_graph()