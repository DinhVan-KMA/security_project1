const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const mysql = require('mysql2');
require('dotenv').config();

const http = require('http');
const https = require('https');
const fs = require('fs');
const { Server } = require('socket.io');

// 🆕 GIẢI PHÁP BẢO MẬT: Tách làm 2 ứng dụng Express độc lập hoàn toàn
const appESP32 = express();     // Chỉ xử lý phần cứng ở cổng 3000
const appDashboard = express(); // Chỉ xử lý giao diện/điều khiển ở cổng 5000

appESP32.use(bodyParser.json());
appDashboard.use(bodyParser.json());

const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, 'server.key')),
    cert: fs.readFileSync(path.join(__dirname, 'server.crt'))
};

// Cấu hình Server độc lập cho từng cổng
const httpServer = http.createServer(appESP32); // Cổng 3000 chỉ chạy appESP32
const httpsServer = https.createServer(sslOptions, appDashboard); // Cổng 5000 chỉ chạy appDashboard

const io = new Server(httpsServer, {
    cors: { origin: "*" }
});

const SECRET_KEY = process.env.SECRET_KEY;
const WEB_ADMIN_TOKEN = process.env.WEB_ADMIN_TOKEN;
const processedHMACs = new Map();

setInterval(() => {
    const now = Date.now();
    for (let [hmac, timeStored] of processedHMACs.entries()) {
        if (now - timeStored > 30000) {
            processedHMACs.delete(hmac);
        }
    }
}, 10000);

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
    device_id: "Chưa có",
    temp: 0,
    soil: 0,
    pump: "OFF",
    fan: "OFF",
    mode: "Auto",
    lastUpdate: "Chưa có dữ liệu"
};

io.on('connection', (socket) => {
    console.log(` Thiết bị kết nối Dashboard qua WebSocket: ${socket.id}`);
    socket.on('disconnect', () => {
        console.log(` Thiết bị ngắt kết nối WebSocket: ${socket.id}`);
    });
});

// Middleware xác thực Token (Chỉ áp dụng cho appDashboard)
const authenticateAdminWeb = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const ip = req.ip.replace('::ffff:', '');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        const logNoToken = {
            device_id: 'WEB_DASHBOARD',
            event_direction: 'Web điều khiển xuống',
            status: 'UNAUTHORIZED ACCESS',
            ip_address: ip,
            details: 'Tấn công API control: Hoàn toàn không gửi kèm mã xác thực Token',
            created_at: new Date()
        };
        db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
            [logNoToken.device_id, logNoToken.event_direction, logNoToken.status, logNoToken.ip_address, logNoToken.details]);
        io.emit('new-log', logNoToken);
        return res.status(401).json({ success: false, message: "Từ chối: Không tìm thấy Token bảo mật! (401)" });
    }

    const tokenReceived = authHeader.split(' ')[1];
    if (tokenReceived !== WEB_ADMIN_TOKEN) {
        const logWrongToken = {
            device_id: 'WEB_DASHBOARD',
            event_direction: 'Web điều khiển xuống',
            status: 'FORBIDDEN ACCESS',
            ip_address: ip,
            details: `Tấn công đoán mò Token: Nhập sai mã băm (${tokenReceived})`,
            created_at: new Date()
        };
        db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
            [logWrongToken.device_id, logWrongToken.event_direction, logWrongToken.status, logWrongToken.ip_address, logWrongToken.details]);
        io.emit('new-log', logWrongToken);
        return res.status(403).json({ success: false, message: "Từ chối: Token không hợp lệ, lệnh bị hủy! (403)" });
    }
    next();
};

// ==========================================
// 🛡️ TUYẾN ĐƯỜNG CỔNG 5000: CHỈ DÀNH CHO DASHBOARD WEB ADMIN
// ==========================================
appDashboard.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
appDashboard.get('/api/node', (req, res) => res.json(nodeState));
appDashboard.get('/api/logs', (req, res) => {
    const sql = "SELECT * FROM security_logs ORDER BY id DESC LIMIT 10";
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});
appDashboard.get('/api/chart', (req, res) => {
    const sql = "SELECT * FROM sensor_data ORDER BY id DESC LIMIT 15";
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results.reverse());
    });
});

appDashboard.post('/api/control', authenticateAdminWeb, (req, res) => {
    const { type, value } = req.body;
    const ip = req.ip.replace('::ffff:', '');

    if (type === 'mode') {
        nodeState.mode = value;
    } else if (nodeState.mode === 'Manual') {
        nodeState[type] = value;
    } else {
        return res.status(400).json({ success: false, message: "Cần chuyển sang thủ công!" });
    }

    const logControlSuccess = {
        device_id: 'WEB_DASHBOARD',
        event_direction: 'Web điều khiển xuống',
        status: 'CONTROL SUCCESS',
        ip_address: ip,
        details: `Admin ra lệnh điều khiển thành công: Đặt ${type} thành ${value}`,
        created_at: new Date()
    };
    db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
        [logControlSuccess.device_id, logControlSuccess.event_direction, logControlSuccess.status, logControlSuccess.ip_address, logControlSuccess.details]);

    io.emit('node-update', nodeState);
    io.emit('new-log', logControlSuccess);
    res.json({ success: true, message: "Đã thực thi lệnh từ Admin hợp pháp." });
});

// ==========================================
// 🔌 TUYẾN ĐƯỜNG CỔNG 3000: ĐỘC QUYỀN KẾT NỐI ESP32 (M2M)
// ==========================================
appESP32.post('/api/sensor', (req, res) => {
    const { device_id, data, hmac_received, timestamp } = req.body;
    if (!data || !timestamp) return res.status(400).send("No data or timestamp missing");

    const devId = device_id || 'UNKNOWN_ESP32';
    const serverTime = Math.floor(Date.now() / 1000);
    const clientTime = parseInt(timestamp);
    const ip = req.ip.replace('::ffff:', '');

    if (processedHMACs.has(hmac_received)) {
        const logReplayHash = {
            device_id: devId, event_direction: 'Gửi từ ESP32 lên', status: 'REPLAY ATTACK DETECTED',
            ip_address: ip, details: `Phát lại mã băm trùng lặp (Dưới 50s)`,
            created_at: new Date() // 🆕 ĐÃ SỬA: Thêm thời gian cho log
        };
        db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
            [logReplayHash.device_id, logReplayHash.event_direction, logReplayHash.status, logReplayHash.ip_address, logReplayHash.details]);
        io.emit('new-log', logReplayHash);
        return res.status(401).send("Gói tin đã bị phát lại!");
    }

    if (Math.abs(serverTime - clientTime) > 30) {
        const logReplayTime = {
            device_id: devId, event_direction: 'Gửi từ ESP32 lên', status: 'REPLAY ATTACK DETECTED',
            ip_address: ip, details: `Gói tin quá hạn: ${serverTime - clientTime}s`,
            created_at: new Date() // 🆕 ĐÃ SỬA: Thêm thời gian cho log
        };
        db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
            [logReplayTime.device_id, logReplayTime.event_direction, logReplayTime.status, logReplayTime.ip_address, logReplayTime.details]);
        io.emit('new-log', logReplayTime);
        return res.status(401).send("Gói tin đã quá hạn!");
    }

    const rawString = `device_id=${devId}&temp=${data.temp}&soil=${data.soil}&fan=${data.fan}&pump=${data.pump}&timestamp=${timestamp}`;
    const calculatedHmac = crypto.createHmac('sha256', SECRET_KEY).update(rawString).digest('hex');

    if (calculatedHmac === hmac_received) {
        processedHMACs.set(hmac_received, Date.now());
        nodeState.device_id = devId;
        nodeState.temp = data.temp;
        nodeState.soil = data.soil;
        nodeState.lastUpdate = new Date().toLocaleString();

        if (nodeState.mode === "Auto") {
            nodeState.pump = data.pump ? "ON" : "OFF";
            nodeState.fan = data.fan ? "ON" : "OFF";
        }

        db.query("INSERT INTO sensor_data (temp, soil, pump, fan) VALUES (?, ?, ?, ?)",
            [nodeState.temp, nodeState.soil, nodeState.pump, nodeState.fan]);

        const logHmacSuccessUp = {
            device_id: devId, event_direction: 'Gửi từ ESP32 lên', status: 'HMAC SUCCESS',
            ip_address: ip, details: `Mã băm: ${hmac_received}`,
            created_at: new Date() // 🆕 ĐÃ SỬA: Thêm thời gian cho log
        };
        db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
            [logHmacSuccessUp.device_id, logHmacSuccessUp.event_direction, logHmacSuccessUp.status, logHmacSuccessUp.ip_address, logHmacSuccessUp.details]);

        const serverTimeDown = Math.floor(Date.now() / 1000);
        const replyString = `mode=${nodeState.mode}&pump=${nodeState.pump}&fan=${nodeState.fan}&timestamp=${serverTimeDown}`;
        const replyHmac = crypto.createHmac('sha256', SECRET_KEY).update(replyString).digest('hex');

        const logHmacSuccessDown = {
            device_id: devId, event_direction: 'Web điều khiển xuống', status: 'HMAC SUCCESS',
            ip_address: ip, details: `Mã băm phản hồi: ${replyHmac}`,
            created_at: new Date() // 🆕 ĐÃ SỬA: Thêm thời gian cho log
        };
        db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
            [logHmacSuccessDown.device_id, logHmacSuccessDown.event_direction, logHmacSuccessDown.status, logHmacSuccessDown.ip_address, logHmacSuccessDown.details]);

        io.emit('new-log', logHmacSuccessUp);
        io.emit('new-log', logHmacSuccessDown);
        io.emit('node-update', nodeState);

        res.status(200).json({
            mode: nodeState.mode, pump: nodeState.pump, fan: nodeState.fan,
            server_timestamp: serverTimeDown, hmac_reply: replyHmac
        });
    } else {
        const logHmacFailed = {
            device_id: devId, event_direction: 'Gửi từ ESP32 lên', status: 'HMAC FAILED',
            ip_address: ip, details: `Nhận hmac lỗi: ${hmac_received}`,
            created_at: new Date() // 🆕 ĐÃ SỬA: Thêm thời gian cho log
        };
        db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
            [logHmacFailed.device_id, logHmacFailed.event_direction, logHmacFailed.status, logHmacFailed.ip_address, logHmacFailed.details]);
        io.emit('new-log', logHmacFailed);
        res.status(403).send("Sai HMAC");
    }
});

// Khởi chạy server độc lập
const ESP32_PORT = 3000;
httpServer.listen(ESP32_PORT, () => {
    console.log(`[ESP32 SECURE PORT] API đang chạy tại: http://localhost:${ESP32_PORT}`);
});

const WEB_PORT = 443;
httpsServer.listen(WEB_PORT, () => {
    console.log(`[Dashboard HTTPS PORT] Web đang chạy tại: https://localhost:${WEB_PORT}`);
});