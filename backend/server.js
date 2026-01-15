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
    // 1. Create domain
    await api.post('/add/domain', {
      domain,
      active: true
    });

    // 2. Create DKIM
    const dkim = await api.post('/add/dkim', {
      domain,
      selector: 'dkim',
      length: 2048
    });

    // 3. Create domain admin (FIXED)
    await api.post('/add/domain-admin', {
      active: 1,
      username: email,
      password: password,
      password2: password,
      domains: [domain],
      force_pw_update: false,
      kind: "domainadmin",
      quota: 0
    });

    // 4. Return success + DKIM
    res.json({
      ok: true,
      message: 'Domain provisioned. Add DNS records.',
      dkim: dkim.data
    });

  } catch (err) {
    console.error("Mailcow error:", err.response?.data || err.message);
    res.status(400).json({
      ok: false,
      error: err.response?.data || err.message
    });
  }
});

app.listen(3000, () => console.log('Backend running on port 3000'));
