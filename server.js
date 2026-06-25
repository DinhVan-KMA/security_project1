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

// Khởi tạo 2 ứng dụng Express độc lập hoàn toàn
const appESP32 = express();     // Xử lý cổng 3000
const appDashboard = express(); // Xử lý giao diện ở cổng 443

appESP32.use(bodyParser.json());
appDashboard.use(bodyParser.json());

const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, 'server.key')),
    cert: fs.readFileSync(path.join(__dirname, 'server.crt'))
};

// Cấu hình Server cho từng cổng
const httpServer = http.createServer(appESP32); // HTTP Cổng 3000 dành cho ESP32
const httpsServer = https.createServer(sslOptions, appDashboard); // HTTPS Cổng 443 dành cho Dashboard

// 🌐 KHỞI TẠO 2 KÊNH SOCKET.IO RIÊNG BIỆT
// Kênh dành cho phần cứng ESP32 (Cổng 3000)
const ioESP32 = new Server(httpServer, {
    cors: { origin: "*" }
});
// Kênh dành cho giao diện người dùng (Cổng 443)
const io = new Server(httpsServer, {
    cors: { origin: "*" }
});

const SECRET_KEY = process.env.SECRET_KEY;
const WEB_ADMIN_TOKEN = process.env.WEB_ADMIN_TOKEN;
const processedHMACs = new Map();

// Luồng dọn dẹp bộ nhớ đệm HMAC chống Replay Attack
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

// Theo dõi kết nối từ Web Dashboard Admin
io.on('connection', (socket) => {
    console.log(`[Dashboard Connected] Giao diện quản trị kết nối qua ID: ${socket.id}`);
    socket.on('disconnect', () => {
        console.log(`[Dashboard Disconnected] Giao diện quản trị ngắt kết nối: ${socket.id}`);
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
// 🛡️ TUYẾN ĐƯỜNG CỔNG 443: CHỈ DÀNH CHO DASHBOARD WEB ADMIN (HTTPS)
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

    // Phát tín hiệu điều khiển realtime xuống thẳng ESP32 qua kênh kết nối WebSocket cổng 3000 đang mở sẵn
    //ioESP32.emit('server-cmd', { mode: nodeState.mode, pump: nodeState.pump, fan: nodeState.fan });

    res.json({ success: true, message: "Đã thực thi lệnh từ Admin hợp pháp." });
});

// ==========================================
// 🔌 HỆ THỐNG WEBSOCKET CỔNG 3000: ĐỘC QUYỀN KẾT NỐI REALTIME ESP32 (M2M)
// ==========================================
ioESP32.on('connection', (socket) => {
    // Trích xuất IP thô của ESP32 kết nối vào Socket
    const ip = socket.handshake.address.replace('::ffff:', '');
    console.log(`[ESP32 CONNECTED] Thiết bị phần cứng đã kết nối qua Socket ID: ${socket.id} - IP: ${ip}`);


    socket.on('sensor-transmit', (jsonData) => {
        const { device_id, data, hmac_received, timestamp } = jsonData;

        if (!data || !timestamp) {
            console.log("[ESP32 ERROR] Thiếu dữ liệu cảm biến hoặc cấu trúc Timestamp");
            return;
        }

        const devId = device_id || 'UNKNOWN_ESP32';
        const serverTime = Math.floor(Date.now() / 1000);
        const clientTime = parseInt(timestamp);

        // 1. KIỂM TRA CHỐNG PHÁT LẠI QUA MÃ BĂM (Replay Attack - Hash Cache)
        if (processedHMACs.has(hmac_received)) {
            const logReplayHash = {
                device_id: devId, event_direction: 'Gửi từ ESP32 lên', status: 'REPLAY ATTACK DETECTED',
                ip_address: ip, details: `Phát lại mã băm trùng lặp trên kênh WebSocket (Dưới 30s)`,
                created_at: new Date()
            };
            db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
                [logReplayHash.device_id, logReplayHash.event_direction, logReplayHash.status, logReplayHash.ip_address, logReplayHash.details]);
            io.emit('new-log', logReplayHash);
            return; // Ngắt xử lý
        }

        // 2. KIỂM TRA CHỐNG PHÁT LẠI QUA ĐỘ LỆCH THỜI GIAN (Replay Attack - Window Time)
        if (Math.abs(serverTime - clientTime) > 30) {
            const logReplayTime = {
                device_id: devId, event_direction: 'Gửi từ ESP32 lên', status: 'REPLAY ATTACK DETECTED',
                ip_address: ip, details: `Gói tin WebSocket quá hạn quy định: Lệch ${serverTime - clientTime} giây`,
                created_at: new Date()
            };
            db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
                [logReplayTime.device_id, logReplayTime.event_direction, logReplayTime.status, logReplayTime.ip_address, logReplayTime.details]);
            io.emit('new-log', logReplayTime);
            return; // Ngắt xử lý
        }

        // 3. TÍNH TOÁN VÀ ĐỐI CHIẾU XÁC THỰC MÃ BĂM HMAC-SHA256 TOÀN VẸN
        const rawString = `device_id=${devId}&temp=${data.temp}&soil=${data.soil}&fan=${data.fan}&pump=${data.pump}&timestamp=${timestamp}`;
        const calculatedHmac = crypto.createHmac('sha256', SECRET_KEY).update(rawString).digest('hex');

        if (calculatedHmac === hmac_received) {
            // Xác thực thành công -> Ghi nhận mã băm vào danh sách đã xử lý
            processedHMACs.set(hmac_received, Date.now());

            nodeState.device_id = devId;
            nodeState.temp = data.temp;
            nodeState.soil = data.soil;
            nodeState.lastUpdate = new Date().toLocaleString();

            if (nodeState.mode === "Auto") {
                nodeState.pump = data.pump ? "ON" : "OFF";
                nodeState.fan = data.fan ? "ON" : "OFF";
            }

            // Lưu dữ liệu vào bảng cảm biến
            db.query("INSERT INTO sensor_data (temp, soil, pump, fan) VALUES (?, ?, ?, ?)",
                [nodeState.temp, nodeState.soil, nodeState.pump, nodeState.fan]);

            // Ghi nhật ký bảo mật thành công cho gói tin lên
            const logHmacSuccessUp = {
                device_id: devId, event_direction: 'Gửi từ ESP32 lên', status: 'HMAC SUCCESS',
                ip_address: ip, details: `Mã băm hợp lệ: ${hmac_received}`,
                created_at: new Date()
            };
            db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
                [logHmacSuccessUp.device_id, logHmacSuccessUp.event_direction, logHmacSuccessUp.status, logHmacSuccessUp.ip_address, logHmacSuccessUp.details]);

            // THIẾT LẬP PHẢN HỒI SONG HƯỚNG TỪ SERVER XUỐNG ESP32
            const serverTimeDown = Math.floor(Date.now() / 1000);
            const replyString = `mode=${nodeState.mode}&pump=${nodeState.pump}&fan=${nodeState.fan}&timestamp=${serverTimeDown}`;
            const replyHmac = crypto.createHmac('sha256', SECRET_KEY).update(replyString).digest('hex');

            // Ghi nhật ký bảo mật thành công cho gói tin xuống
            const logHmacSuccessDown = {
                device_id: devId, event_direction: 'Web điều khiển xuống', status: 'HMAC SUCCESS',
                ip_address: ip, details: `Mã băm phản hồi an toàn: ${replyHmac}`,
                created_at: new Date()
            };
            db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
                [logHmacSuccessDown.device_id, logHmacSuccessDown.event_direction, logHmacSuccessDown.status, logHmacSuccessDown.ip_address, logHmacSuccessDown.details]);

            // Đẩy tất cả nhật ký, cập nhật trạng thái đồng bộ sang Dashboard (Cổng 443) bằng luồng realtime
            io.emit('new-log', logHmacSuccessUp);
            io.emit('new-log', logHmacSuccessDown);
            io.emit('node-update', nodeState);

            // PHẢN HỒI REALTIME LẠI CHO CHÍNH CON ESP32 ĐANG KẾT NỐI
            socket.emit('server-reply', {
                mode: nodeState.mode,
                pump: nodeState.pump,
                fan: nodeState.fan,
                server_timestamp: serverTimeDown,
                hmac_reply: replyHmac
            });

        } else {
            // Trường hợp sai mã HMAC -> Phát hiện tấn công giả mạo thiết bị phần cứng
            const logHmacFailed = {
                device_id: devId, event_direction: 'Gửi từ ESP32 lên', status: 'HMAC FAILED',
                ip_address: ip, details: `Cảnh báo giả mạo! Nhận mã băm sai lệch: ${hmac_received}`,
                created_at: new Date()
            };
            db.query("INSERT INTO security_logs (device_id, event_direction, status, ip_address, details) VALUES (?, ?, ?, ?, ?)",
                [logHmacFailed.device_id, logHmacFailed.event_direction, logHmacFailed.status, logHmacFailed.ip_address, logHmacFailed.details]);

            io.emit('new-log', logHmacFailed);

            // Thông báo lỗi thẳng về cho Client ESP32 biết
            socket.emit('server-error', { message: "Xác thực HMAC thất bại!" });
        }
    });

    socket.on('disconnect', () => {
        console.log(`[ESP32 DISCONNECTED] Thiết bị ngắt kết nối cổng 3000, ID: ${socket.id}`);
    });
});

// Khởi chạy hệ thống Server độc lập hoàn toàn
const ESP32_PORT = 3000;
httpServer.listen(ESP32_PORT, () => {
    console.log(`[ESP32 REALTIME WEBSOCKET PORT] Chờ kết nối thiết bị tại: ws://localhost:${ESP32_PORT}`);
});

const WEB_PORT = 443;
httpsServer.listen(WEB_PORT, () => {
    console.log(`[Dashboard HTTPS PORT] Giao diện người dùng đang chạy tại: https://localhost:${WEB_PORT}`);
});