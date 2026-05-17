const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const mysql = require('mysql2');
require('dotenv').config();
const app = express();
app.use(bodyParser.json());

const SECRET_KEY = process.env.SECRET_KEY;

// Cấu hình kết nối MySQL
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

// API để Dashboard lấy trạng thái hiện tại
app.get('/api/node', (req, res) => res.json(nodeState));

// API lấy 10 nhật ký mới nhất từ Database
app.get('/api/logs', (req, res) => {
    const sql = "SELECT * FROM security_logs ORDER BY id DESC LIMIT 10";
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

// --- API NHẬN DỮ LIỆU TỪ ESP32 ---
app.post('/api/sensor', (req, res) => {
    const { data, hmac_received } = req.body;
    if (!data) return res.status(400).send("No data");

    const rawString = `temp=${data.temp}&soil=${data.soil}&fan=${data.fan}&pump=${data.pump}`;
    const calculatedHmac = crypto.createHmac('sha256', SECRET_KEY).update(rawString).digest('hex');
    const ip = req.ip.replace('::ffff:', ''); // Lấy IP người gửi

    if (calculatedHmac === hmac_received) {
        // 1. Cập nhật trạng thái vào bộ nhớ (NodeState)
        nodeState.temp = data.temp;
        nodeState.soil = data.soil;
        nodeState.lastUpdate = new Date().toLocaleString();

        if (nodeState.mode === "Auto") {
            nodeState.pump = data.pump ? "ON" : "OFF";
            nodeState.fan = data.fan ? "ON" : "OFF";
        }

        // 2. Lưu vào Database (Sensor data & Security log thành công)
        db.query("INSERT INTO sensor_data (temp, soil, pump, fan) VALUES (?, ?, ?, ?)",
            [nodeState.temp, nodeState.soil, nodeState.pump, nodeState.fan]);

        db.query("INSERT INTO security_logs (event_type, ip_address, details) VALUES (?, ?, ?)",
            ['HMAC_SUCCESS', ip, hmac_received]);

        //console.log(`[${nodeState.mode}] Update: T=${data.temp}, S=${data.soil}, P=${nodeState.pump}, F=${nodeState.fan}`);

        // 3. Phản hồi lệnh cho ESP32
        res.status(200).json({
            mode: nodeState.mode,
            pump: nodeState.pump,
            fan: nodeState.fan
        });
    } else {
        // Lưu nhật ký thất bại khi sai HMAC
        db.query("INSERT INTO security_logs (event_type, ip_address, details) VALUES (?, ?, ?)",
            ['HMAC_FAILED', ip, `Cảnh báo: Sai mã băm! Nhận được: ${hmac_received.substring(0, 10)}...`]);

        console.warn(`[WARNING] Sai HMAC từ IP: ${ip}`);
        res.status(403).send("Sai HMAC");
    }
});
// --- API ĐIỀU KHIỂN TỪ WEB ---
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
app.get('/api/chart', (req, res) => {

    const sql = `
        SELECT * FROM sensor_data
        ORDER BY id DESC
        LIMIT 15
    `;

    db.query(sql, (err, results) => {

        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }

        // Đảo lại cho đúng thứ tự thời gian
        res.json(results.reverse());
    });
});
app.listen(3000, () => {

    console.log("Server đang chạy tại: http://localhost:3000");
});