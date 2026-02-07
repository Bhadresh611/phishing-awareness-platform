require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

// === Config ===
const {
  MONGODB_URI,
  ADMIN_EMAIL,
  ADMIN_PASSWORD,
  JWT_SECRET,
  SMTP_SERVICE,
  SMTP_USER,
  SMTP_PASS,
} = process.env;

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../frontend')));

const PORT = process.env.PORT || 5000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// === Admin Verification Middleware ===
function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No authorization header provided' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    console.error('❌Invalid token: ', err.message);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// === DB Connect ===
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=>console.log('✅ MongoDB Connected'))
  .catch(err=>console.error('❌ Mongo Error:', err));

// === Schemas ===
const campaignSchema = new mongoose.Schema({
  name: String,
  targetGroup: String,
  startDate: String,
  endDate: String,
  emailTemplate: String,
  status: { type: String, default: 'Active' },
  sent: { type: Number, default: 0 },
  clicked: { type: Number, default: 0 },
  reported: { type: Number, default: 0 },
  submitted: { type: Number, default: 0 },
  ignored: { type: Number, default: 0 },
});
const Campaign = mongoose.model('Campaign', campaignSchema);

const trackingSchema = new mongoose.Schema({
  campaignId: String,
  userId: String,
  event: { type: String, enum: ['clicked', 'reported', 'submitted'] },
  timestamp: { type: Date, default: Date.now },
});
const Tracking = mongoose.model('Tracking', trackingSchema);

const scoreSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  totalScore: { type: Number, default: 0 },
  level: { type: String, default: 'Beginner' },
});
const AwarenessScore = mongoose.model('AwarenessScore', scoreSchema);

// === Routes ===
app.get('/', (req, res) => {
  res.send('🚀 Backend + MongoDB + Awareness Tracking Connected!');
});

// === Admin Login ===
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ message: '✅ Login successful', token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

// === Campaign CRUD ===
app.post('/api/campaigns', verifyAdmin, async (req, res) => {
  const campaign = new Campaign(req.body);
  await campaign.save();
  res.json({ message: '✅ Campaign saved', campaign });
});

// ✅ Auto-update campaign statuses when fetched
app.get('/api/campaigns', async (req, res) => {
  try {
    const campaigns = await Campaign.find({});
    const today = new Date();

    for (const c of campaigns) {
      const startDate = new Date(c.startDate);
      const endDate = new Date(c.endDate);
      let newStatus = c.status;

      if (endDate < today) {
        newStatus = 'Completed';
      } else if (startDate > today) {
        newStatus = 'Draft';
      } else if (startDate <= today && endDate >= today) {
        newStatus = 'Active';
      }

      // 🩵 Only save if status actually changed
      if (newStatus !== c.status) {
        console.log(`🔄 Updated campaign "${c.name}" → ${newStatus}`);
        c.status = newStatus;
        await c.save();
      }
    }

    res.json(campaigns);
  } catch (err) {
    console.error('❌ Error fetching campaigns:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/campaigns/:id', async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id);
    if (!campaign) return res.status(404).json({ error: 'Campaign not found' });
    res.json(campaign);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/campaigns/:id', verifyAdmin, async (req, res) => {
  try {
    const updated = await Campaign.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updated) return res.status(404).json({ error: 'Campaign not found' });
    res.json({ message: '✅ Campaign updated', updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/campaigns/:id', verifyAdmin, async (req, res) => {
  try {
    const deleted = await Campaign.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Campaign not found' });
    res.json({ message: '✅ Campaign deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === Send Simulation Email ===
app.post('/api/send-email', verifyAdmin, async (req, res) => {
  const { campaignId, recipients, subject } = req.body;

  if (!campaignId || !recipients || recipients.length === 0) {
    return res.status(400).json({ error: 'Missing campaign or recipients' });
  }

  try {
    const transporter = nodemailer.createTransport({
      service: SMTP_SERVICE,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });

    for (const email of recipients) {
      const clickLink  = `${BASE_URL}/track?cid=${campaignId}&uid=${encodeURIComponent(email)}&event=clicked`;
      const reportLink = `${BASE_URL}/track?cid=${campaignId}&uid=${encodeURIComponent(email)}&event=reported`;


      // 🧠 Fetch the campaign to get its custom template
      const campaign = await Campaign.findById(campaignId);

      // 🔗 Replace placeholders with dynamic tracking URLs
      let htmlBody = campaign?.emailTemplate || `
        <p>Dear User,</p>
        <p>This is a phishing simulation test.</p>
        <p><a href="{{phish_link}}">Click Here</a> or <a href="{{report_link}}">Report</a></p>
      `;

      htmlBody = htmlBody
        .replace(/\{\{phish_link\}\}/g, clickLink)
        .replace(/\{\{report_link\}\}/g, reportLink);

      // ✉️ Send the email
      await transporter.sendMail({
        from: '"Security Team" <no-reply@phishing-sim.com>',
        to: email,
        subject: subject || campaign?.name || '⚠️ Phishing Awareness Email',
        html: htmlBody,
      });
    }

    // ✅ Update campaign “sent” count
    const campaignData = await Campaign.findById(campaignId);
    if (campaignData) {
      campaignData.sent = (campaignData.sent || 0) + recipients.length;
      await campaignData.save();
    }

    res.json({ message: `✅ Sent to ${recipients.length} users` });
  } catch (err) {
    console.error('❌ Send Email Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// === Awareness Tracking + Scoring ===
app.get('/track', async (req, res) => {
  const { cid, uid, event } = req.query;
  if (!cid || !uid || !event) return res.status(400).send('Missing parameters');

  try {
    // 1️⃣ Log tracking event
    const log = new Tracking({ campaignId: cid, userId: uid, event });
    await log.save();
    console.log('📩 Tracking Event:', log);

    // 2️⃣ Update campaign counts
    const campaign = await Campaign.findById(cid);
    if (campaign) {
      if (event === 'clicked') campaign.clicked = (campaign.clicked || 0) + 1;
      if (event === 'reported') campaign.reported = (campaign.reported || 0) + 1;
      if (event === 'submitted') campaign.submitted = (campaign.submitted || 0) + 1;

      // Auto-calculate ignored after every event
      const sent = campaign.sent || 0;
      const totalActions = (campaign.clicked || 0) + (campaign.reported || 0) + (campaign.submitted || 0);
      campaign.ignored = Math.max(sent - totalActions, 0);

      await campaign.save();
    }

    // 3️⃣ Update awareness score
    const scoreChange =
      event === 'reported' ? 10 :
      event === 'clicked'  ? -10 :
      event === 'submitted'? -20 : 0;

    let scoreDoc = await AwarenessScore.findOne({ userId: uid });
    if (!scoreDoc) scoreDoc = new AwarenessScore({ userId: uid });

    scoreDoc.totalScore += scoreChange;

    if (scoreDoc.totalScore >= 80) scoreDoc.level = 'Expert';
    else if (scoreDoc.totalScore >= 50) scoreDoc.level = 'Intermediate';
    else scoreDoc.level = 'Beginner';

    await scoreDoc.save();
    console.log(`🎯 ${uid} new score: ${scoreDoc.totalScore} (${scoreDoc.level})`);

    // 4️⃣ Redirects for user-facing pages
        const FRONTEND_URL = BASE_URL;
    if (event === 'clicked') return res.redirect(`${FRONTEND_URL}/login.html?cid=${cid}&uid=${encodeURIComponent(uid)}`);
    if (event === 'submitted') return res.redirect(`${FRONTEND_URL}/awareness.html`);
    if (event === 'reported') return res.redirect(`${FRONTEND_URL}/reported.html`);
    // if (event === 'ignored') return res.redirect(`${FRONTEND_URL}/ignored.html`);

    res.send('✅ Event Recorded');
  } catch (err) {
    console.error('❌ Tracking Error:', err);
    res.status(500).send('Server Error');
  }
});

// === Scores ===
app.post('/api/scores', async (req, res) => {
  const { userId, quizScore } = req.body;
  if (!userId) return res.status(400).json({ error: "Missing userId" });

  let scoreDoc = await AwarenessScore.findOne({ userId });
  if (!scoreDoc) scoreDoc = new AwarenessScore({ userId });

  scoreDoc.totalScore += (quizScore || 0) * 5;
  if (scoreDoc.totalScore >= 80) scoreDoc.level = "Expert";
  else if (scoreDoc.totalScore >= 50) scoreDoc.level = "Intermediate";
  else scoreDoc.level = "Beginner";

  await scoreDoc.save();
  res.json({ message: "✅ Quiz score updated", scoreDoc });
});

app.get('/api/scores', async (req, res) => {
  const scores = await AwarenessScore.find().sort({ totalScore: -1 });
  res.json(scores);
});

// === Tracking Logs for Reports ===
app.get('/api/tracking', verifyAdmin, async (req, res) => {
  try{
  const logs = await Tracking.find().sort({ timestamp: -1 });
  res.json(logs);
  } catch (err) {
    console.error('❌ Error Fetching tracking logs:', err);
    res.status(500).json({ error: err.message});
  }

});

// === Start Server ===
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
