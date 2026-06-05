const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const mysql = require('mysql2');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

const SECRET_KEY = process.env.SECRET_KEY;

// Cấu hình kết nối MySQL sử dụng biến môi trường hệ thống của bạn
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) console.error("Lỗi kết nối MySQL:", err);
    else console.log("Đã kết nối Database thành công!");
});

let nodeState = {
    temp: 0,
    soil: 0,
    pump: "OFF",
    fan: "OFF",
    mode: "Auto",
    lastUpdate: "Chưa có dữ liệu"
};

// --- ROUTES GIAO DIỆN ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// API để Dashboard lấy trạng thái hiện tại của thiết bị và cảm biến
app.get('/api/node', (req, res) => res.json(nodeState));

// API lấy 10 nhật ký bảo mật mới nhất (Trả về toàn bộ để lưu trữ, Web sẽ tự lọc)
app.get('/api/logs', (req, res) => {
    const sql = "SELECT * FROM security_logs ORDER BY id DESC LIMIT 10";
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

// --- API NHẬN DỮ LIỆU TỪ ESP32 & XỬ LÝ HMAC TWO-WAY ---
app.post('/api/sensor', (req, res) => {
    const { data, hmac_received, timestamp } = req.body;
    if (!data || !timestamp) return res.status(400).send("No data or timestamp missing");
    const serverTime = Math.floor(Date.now() / 1000);
    const clientTime = parseInt(timestamp);
    // Nếu gói tin cũ quá 10 giây -> Từ chối phát lại
    if (Math.abs(serverTime - clientTime) > 10) {
        const ip = req.ip.replace('::ffff:', '');
        db.query("INSERT INTO security_logs (event_direction, status, ip_address, details) VALUES (?, ?, ?, ?)",
            ['Gửi từ ESP32 lên', 'REPLAY ATTACK DETECTED', ip, `Gói tin quá hạn: ${serverTime - clientTime}s`]);

        console.warn(`[WARNING] Phát hiện tấn công phát lại từ IP: ${ip}`);
        return res.status(401).send("Gói tin đã quá hạn (Replay Attack)");
    }
    // Xây dựng chuỗi thô đồng bộ định dạng với phần cứng
    const rawString = `temp=${data.temp}&soil=${data.soil}&fan=${data.fan}&pump=${data.pump}&timestamp=${timestamp}`;
    const calculatedHmac = crypto.createHmac('sha256', SECRET_KEY).update(rawString).digest('hex');
    const ip = req.ip.replace('::ffff:', ''); // Chuẩn hóa chuỗi IP người gửi

    if (calculatedHmac === hmac_received) {
        // 1. Cập nhật dữ liệu vào bộ nhớ tạm hệ thống
        nodeState.temp = data.temp;
        nodeState.soil = data.soil;
        nodeState.lastUpdate = new Date().toLocaleString();

        if (nodeState.mode === "Auto") {
            nodeState.pump = data.pump ? "ON" : "OFF";
            nodeState.fan = data.fan ? "ON" : "OFF";
        }

        // 2. Ghi chép dữ liệu cảm biến thực tế vào Database
        db.query("INSERT INTO sensor_data (temp, soil, pump, fan) VALUES (?, ?, ?, ?)",
            [nodeState.temp, nodeState.soil, nodeState.pump, nodeState.fan]);

        // 3. Ghi Nhật ký Bảo mật chiều LÊN (Thành công)
        db.query("INSERT INTO security_logs (event_direction, status, ip_address, details) VALUES (?, ?, ?, ?)",
            ['Gửi từ ESP32 lên', 'HMAC SUCCESS', ip, hmac_received]);

        // 4. Sinh mã băm HMAC bảo vệ chiều XUỐNG (Lệnh điều khiển phát đi từ Web)
        const replyString = `mode=${nodeState.mode}&pump=${nodeState.pump}&fan=${nodeState.fan}&timestamp=${timestamp}`;
        const replyHmac = crypto.createHmac('sha256', SECRET_KEY).update(replyString).digest('hex');

        // Ghi Nhật ký Bảo mật chiều XUỐNG vào Database làm bằng chứng toàn vẹn
        db.query("INSERT INTO security_logs (event_direction, status, ip_address, details) VALUES (?, ?, ?, ?)",
            ['Web điều khiển xuống', 'HMAC SUCCESS', '127.0.0.1', replyHmac]);

        // Trả kết quả kèm chữ ký số về cho ESP32 xác thực
        res.status(200).json({
            mode: nodeState.mode,
            pump: nodeState.pump,
            fan: nodeState.fan,
            hmac_reply: replyHmac
        });
    } else {
        // Lưu vết sự cố tấn công/sai lệch mã băm vào DB để điều tra
        db.query("INSERT INTO security_logs (event_direction, status, ip_address, details) VALUES (?, ?, ?, ?)",
            ['Gửi từ ESP32 lên', 'HMAC FAILED', ip, `Nhận hmac lỗi: ${hmac_received}`]);

        console.warn(`[WARNING] Sai HMAC từ IP: ${ip}`);
        res.status(403).send("Sai HMAC");
    }
});

// --- API ĐIỀU KHIỂN TỪ GIAO DIỆN WEB ---
app.post('/api/control', (req, res) => {
    const { type, value } = req.body;

    if (type === 'mode') {
        nodeState.mode = value;
        console.log(">>> Đã chuyển sang chế độ:", value);
    } else if (nodeState.mode === 'Manual') {
        nodeState[type] = value;
        console.log(`>>> [Manual] ${type} -> ${value}`);
    } else {
        return res.status(400).json({ success: false, message: "Cần chuyển sang thủ công!" });
    }

    res.json({ success: true });
});

// API Lấy dữ liệu lịch sử (Giữ nguyên cấu trúc /api/chart và giới hạn LIMIT 15 của bạn)
app.get('/api/chart', (req, res) => {
    const sql = "SELECT * FROM sensor_data ORDER BY id DESC LIMIT 15";
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results.reverse()); // Đảo mảng để biểu đồ chạy đúng trục thời gian từ trái qua phải
    });
});

app.listen(3000, () => {
    console.log("Server đang chạy mượt mà tại: http://localhost:3000");
});