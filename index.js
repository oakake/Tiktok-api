require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const multer = require('multer');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const CLIENT_KEY    = process.env.TIKTOK_CLIENT_KEY    || 'YOUR_CLIENT_KEY';
const CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET || 'YOUR_CLIENT_SECRET';
const REDIRECT_URI  = process.env.TIKTOK_REDIRECT_URI  || 'http://localhost:5000/auth/callback';

// ─── STORAGE (in-memory; use a DB in production) ──────────────────────────────
const tokenStore = {}; // { [userId]: { access_token, refresh_token, expires_at } }
const pkceStore  = {}; // { [state]: code_verifier }

// ─── MULTER (video upload) ────────────────────────────────────────────────────
const upload = multer({ dest: 'uploads/' });

// ─── PKCE HELPERS ─────────────────────────────────────────────────────────────
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}
function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}


// ════════════════════════════════════════════════════════════════════════════
// 1. OAUTH FLOW
// ════════════════════════════════════════════════════════════════════════════

/**
 * GET /auth/login
 * Redirects the user to TikTok's authorization page.
 */
app.get('/auth/login', (req, res) => {
  const csrfState    = Math.random().toString(36).substring(2);
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // เก็บ verifier ไว้จับคู่ตอน callback
  pkceStore[csrfState] = codeVerifier;

  res.cookie('csrfState', csrfState, { maxAge: 60000, httpOnly: true });

  const params = new URLSearchParams({
    client_key:             CLIENT_KEY,
    response_type:          'code',
    scope:                  'user.info.basic,video.publish',
    redirect_uri:           REDIRECT_URI,
    state:                  csrfState,
    code_challenge:         codeChallenge,
    code_challenge_method:  'S256',
  });

  res.redirect(`https://www.tiktok.com/v2/auth/authorize/?${params.toString()}`);
});


/**
 * GET /auth/callback
 * TikTok redirects here after the user approves access.
 * แลก code → access_token
 */
app.get('/auth/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // ตรวจสอบ CSRF
  if (state !== req.cookies.csrfState) {
    return res.status(403).json({ error: 'State mismatch – possible CSRF attack' });
  }

  if (error) {
    return res.status(400).json({ error, error_description });
  }

  try {
    const tokenRes = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_key:    CLIENT_KEY,
        client_secret: CLIENT_SECRET,
        code,
        grant_type:     'authorization_code',
        redirect_uri:   REDIRECT_URI,
        code_verifier:  pkceStore[state] || '',
      }),
    });

    const tokenData = await tokenRes.json();

    if (tokenData.error) {
      return res.status(400).json(tokenData);
    }

    const { access_token, refresh_token, expires_in, open_id } = tokenData;

    // เก็บ token (ใน production ควรเก็บใน database)
    tokenStore[open_id] = {
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000,
    };

    res.json({
      message: 'Login สำเร็จ!',
      open_id,
      access_token,
      expires_in,
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});


/**
 * POST /auth/refresh
 * Body: { open_id }
 * Refresh access_token ก่อนหมดอายุ
 */
app.post('/auth/refresh', async (req, res) => {
  const { open_id } = req.body;
  const stored = tokenStore[open_id];

  if (!stored) {
    return res.status(404).json({ error: 'ไม่พบ token สำหรับ user นี้' });
  }

  try {
    const refreshRes = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_key:    CLIENT_KEY,
        client_secret: CLIENT_SECRET,
        grant_type:    'refresh_token',
        refresh_token: stored.refresh_token,
      }),
    });

    const data = await refreshRes.json();

    if (data.error) {
      return res.status(400).json(data);
    }

    // อัปเดต token
    tokenStore[open_id] = {
      access_token:  data.access_token,
      refresh_token: data.refresh_token,
      expires_at:    Date.now() + data.expires_in * 1000,
    };

    res.json({ message: 'Refresh token สำเร็จ!', access_token: data.access_token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ════════════════════════════════════════════════════════════════════════════
// 2. USER INFO
// ════════════════════════════════════════════════════════════════════════════

/**
 * GET /user/info?open_id=xxx
 * ดึงข้อมูลโปรไฟล์ผู้ใช้
 */
app.get('/user/info', async (req, res) => {
  const { open_id } = req.query;
  const stored = tokenStore[open_id];

  if (!stored) {
    return res.status(401).json({ error: 'กรุณา login ก่อน' });
  }

  try {
    const infoRes = await fetch(
      'https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name',
      {
        headers: { Authorization: `Bearer ${stored.access_token}` },
      }
    );

    const data = await infoRes.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ════════════════════════════════════════════════════════════════════════════
// 3. VIDEO POSTING (Content Posting API)
// ════════════════════════════════════════════════════════════════════════════

/**
 * POST /video/upload
 * Body (multipart/form-data):
 *   - open_id  : string
 *   - video    : file
 *   - title    : string (caption ของวิดีโอ)
 *   - privacy  : "PUBLIC_TO_EVERYONE" | "MUTUAL_FOLLOW_FRIENDS" | "FOLLOWER_OF_CREATOR" | "SELF_ONLY"
 *
 * ขั้นตอน:
 *   1. Init upload → รับ upload_url และ video_id
 *   2. PUT วิดีโอขึ้น upload_url
 *   3. Publish วิดีโอ
 */
app.post('/video/upload', upload.single('video'), async (req, res) => {
  const { open_id, title, privacy = 'SELF_ONLY' } = req.body;
  const stored = tokenStore[open_id];

  if (!stored) {
    return res.status(401).json({ error: 'กรุณา login ก่อน' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'กรุณาแนบไฟล์วิดีโอ' });
  }

  const videoPath = req.file.path;
  const videoSize = req.file.size;

  try {
    // ── Step 1: Init Upload ──────────────────────────────────────────────
    const initRes = await fetch('https://open.tiktokapis.com/v2/post/publish/video/init/', {
      method: 'POST',
      headers: {
        Authorization:  `Bearer ${stored.access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      },
      body: JSON.stringify({
        post_info: {
          title,
          privacy_level:      privacy,
          disable_duet:       false,
          disable_comment:    false,
          disable_stitch:     false,
          video_cover_timestamp_ms: 1000,
        },
        source_info: {
          source:     'FILE_UPLOAD',
          video_size: videoSize,
          chunk_size: videoSize,   // อัปโหลดเป็น chunk เดียว
          total_chunk_count: 1,
        },
      }),
    });

    const initData = await initRes.json();

    if (initData.error?.code !== 'ok') {
      return res.status(400).json({ step: 'init', ...initData });
    }

    const { publish_id, upload_url } = initData.data;

    // ── Step 2: Upload Video File ────────────────────────────────────────
    const videoBuffer = fs.readFileSync(videoPath);

    const uploadRes = await fetch(upload_url, {
      method:  'PUT',
      headers: {
        'Content-Type':   'video/mp4',
        'Content-Length': videoSize,
        'Content-Range':  `bytes 0-${videoSize - 1}/${videoSize}`,
      },
      body: videoBuffer,
    });

    if (!uploadRes.ok) {
      const uploadErr = await uploadRes.text();
      return res.status(400).json({ step: 'upload', error: uploadErr });
    }

    // ── Step 3: Publish ──────────────────────────────────────────────────
    const publishRes = await fetch('https://open.tiktokapis.com/v2/post/publish/status/fetch/', {
      method: 'POST',
      headers: {
        Authorization:  `Bearer ${stored.access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      },
      body: JSON.stringify({ publish_id }),
    });

    const publishData = await publishRes.json();

    // ลบไฟล์ชั่วคราว
    fs.unlinkSync(videoPath);

    res.json({
      message:    'อัปโหลดวิดีโอสำเร็จ!',
      publish_id,
      status:     publishData,
    });
  } catch (err) {
    // ลบไฟล์ชั่วคราวกรณีเกิด error
    if (fs.existsSync(videoPath)) fs.unlinkSync(videoPath);
    res.status(500).json({ error: err.message });
  }
});


/**
 * GET /video/status?open_id=xxx&publish_id=xxx
 * ตรวจสอบสถานะการโพสต์วิดีโอ
 */
app.get('/video/status', async (req, res) => {
  const { open_id, publish_id } = req.query;
  const stored = tokenStore[open_id];

  if (!stored) {
    return res.status(401).json({ error: 'กรุณา login ก่อน' });
  }

  try {
    const statusRes = await fetch('https://open.tiktokapis.com/v2/post/publish/status/fetch/', {
      method: 'POST',
      headers: {
        Authorization:  `Bearer ${stored.access_token}`,
        'Content-Type': 'application/json; charset=UTF-8',
      },
      body: JSON.stringify({ publish_id }),
    });

    const data = await statusRes.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ─── START SERVER ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ TikTok API Server กำลังทำงานที่ http://localhost:${PORT}`);
  console.log(`   Login:         http://localhost:${PORT}/auth/login`);
  console.log(`   Upload Video:  POST http://localhost:${PORT}/video/upload`);
});