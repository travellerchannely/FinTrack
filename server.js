const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'db', 'fintrack.json');

app.use(express.json({ limit: '100mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let DB = null;

function loadDB() {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (fs.existsSync(DB_PATH)) {
    try {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      DB = JSON.parse(raw);
      console.log('Loaded DB: ' + (DB.transactions?.length || 0) + ' transactions');
    } catch (e) {
      console.error('Failed to parse DB:', e.message);
      DB = null;
    }
  }
}

function saveDBToFile() {
  try {
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify(DB), 'utf8');
  } catch (e) {
    console.error('Failed to save DB:', e.message);
  }
}

app.get('/api/db', (req, res) => {
  if (DB) { res.json(DB); } else { res.json(null); }
});

app.put('/api/db', (req, res) => {
  DB = req.body;
  saveDBToFile();
  res.json({ ok: true });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    transactions: DB?.transactions?.length || 0,
    sites: Object.keys(DB?.sites || {}).length,
    uptime: process.uptime()
  });
});

app.get('/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

loadDB();
app.listen(PORT, '0.0.0.0', () => {
  console.log('FinTrack server running on port ' + PORT);
});