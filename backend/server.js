import express from 'express';
import cors from 'cors';
import axios from 'axios';

const app = express();
app.use(express.json());
app.use(cors());

const { MAILCOW_URL, MAILCOW_API_KEY } = process.env;
const api = axios.create({
  baseURL: `${MAILCOW_URL}/api/v1`,
  headers: { 'X-API-Key': MAILCOW_API_KEY }
});

app.post('/api/provision', async (req, res) => {
  const { domain, email, password } = req.body;
  try {
    await api.post('/add/domain', { domain, active: true });
    const dkim = await api.post('/add/dkim', { domain, selector: 'dkim', length: 2048 });
    await api.post('/add/domain-admin', { username: email, password, domains: [domain] });
    res.json({ ok: true, message: 'Domain provisioned. Add DNS records.', dkim: dkim.data });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.response?.data || err.message });
  }
});

app.listen(3000, () => console.log('Backend running on port 3000'));
