import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import fs from "fs/promises";
import { nanoid } from "nanoid";
import path from "path";

const ROOT = process.cwd();
const PUBLIC_DIR = path.resolve(ROOT, "public");
const DB_PATH = process.env.DB_PATH || path.resolve(ROOT, "db.json");

const app = express();
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


console.log("[MVP] ROOT:", ROOT);
console.log("[MVP] PUBLIC_DIR:", PUBLIC_DIR);
console.log("[MVP] DB_PATH:", DB_PATH);

/* ---------------- Helpers ---------------- */
async function loadDB() {
    try {
      const raw = await fs.readFile(DB_PATH, "utf-8");
      const db = JSON.parse(raw);
  
      // Normalize: ensure arrays exist
      db.users = Array.isArray(db.users) ? db.users : [];
      db.sessions = Array.isArray(db.sessions) ? db.sessions : [];
      db.messages = Array.isArray(db.messages) ? db.messages : [];
      db.resetTokens = Array.isArray(db.resetTokens) ? db.resetTokens : []; // NEW
  
      // Normalize: linkedIn -> linkedin
      for (const u of db.users) {
        if (u && u.linkedIn && !u.linkedin) u.linkedin = u.linkedIn;
        if (u) delete u.linkedIn;
      }
      return db;
    } catch {
      const empty = { users: [], sessions: [], messages: [], resetTokens: [] };
      await fs.writeFile(DB_PATH, JSON.stringify(empty, null, 2), "utf-8");
      return empty;
    }
  }
  
  
async function saveDB(db) {
  await fs.writeFile(DB_PATH, JSON.stringify(db, null, 2), "utf-8");
}
function sanitizeString(s) {
  if (typeof s !== "string") return "";
  return s.trim();
}
function parseSkills(skillsStr) {
  return sanitizeString(skillsStr)
    .toLowerCase()
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
function toInt(n) {
  const x = parseInt(n, 10);
  return Number.isFinite(x) && x >= 0 ? x : 0;
}
function roleCategory(role = "") {
  const r = role.toLowerCase();
  if (r.includes("technical")) return "technical";
  if (r.includes("business") || r.includes("gt-m") || r.includes("go-to-market"))
    return "business";
  return "other";
}
function createSession(email) {
  return { id: nanoid(), email, createdAt: Date.now() };
}
function authMiddleware(req, res, next) {
  const qToken = req.query.token;
  const auth = req.headers.authorization || "";
  const headerToken = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  const token = qToken || headerToken;
  if (!token) return res.status(401).json({ error: "Missing token" });
  req.token = token;
  next();
}

/* --------------- Matching (with scarcity) ---------------
Base score:
  shared skills + industry(+2) + commitment(+1)
Scarcity rule (based on SEEKER 'a'):
  if a.teamTech >= 2 → boost 'business' candidates (+3), mildly penalize 'technical' (-1)
  if a.teamBiz  >= 2 → boost 'technical' candidates (+3), mildly penalize 'business'  (-1)
*/
function matchScore(a, b) {
  const skillsA = parseSkills(a.skills);
  const skillsB = parseSkills(b.skills);
  const shared = skillsA.filter((s) => skillsB.includes(s)).length;

  const industryMatch =
    a.industry?.toLowerCase() === b.industry?.toLowerCase() ? 2 : 0;
  const commitmentMatch =
    a.commitment?.toLowerCase() === b.commitment?.toLowerCase() ? 1 : 0;

  const techCount = toInt(a.teamTech);
  const bizCount = toInt(a.teamBiz);
  const bCat = roleCategory(b.role);

  let scarcityBonus = 0;
  if (techCount >= 2) {
    if (bCat === "business") scarcityBonus += 3;
    if (bCat === "technical") scarcityBonus -= 1;
  }
  if (bizCount >= 2) {
    if (bCat === "technical") scarcityBonus += 3;
    if (bCat === "business") scarcityBonus -= 1;
  }

  return shared + industryMatch + commitmentMatch + scarcityBonus;
}

/* ---------------- Middleware & Static ---------------- */
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(PUBLIC_DIR));

// Root → index.html (explicit)
app.get("/", (req, res) => {
  res.sendFile("index.html", { root: PUBLIC_DIR }, (err) => {
    if (err) {
      console.error("Error sending index.html:", err);
      res.status(500).send("index.html not found in /public.");
    }
  });
});

/* ---------------- Health ---------------- */
app.get("/api/health", (req, res) => res.json({ ok: true }));

/* ---------------- Auth & Signup ---------------- */
// Sign-up (create or update) — now requires username + password
import bcrypt from "bcryptjs"; // <-- add this at the top with other imports

app.post("/api/signup", async (req, res) => {
  const {
    username,           // NEW
    password,           // NEW
    name,
    email,
    skills,
    role,
    industry,
    commitment,
    teamTech,
    teamBiz,
    linkedin,
    linkedIn
  } = req.body || {};

  const clean = {
    username: sanitizeString(username).toLowerCase(), // store lowercase for uniqueness
    name: sanitizeString(name),
    email: sanitizeString(email).toLowerCase(),
    skills: sanitizeString(skills),
    role: sanitizeString(role),
    industry: sanitizeString(industry),
    commitment: sanitizeString(commitment),
    teamTech: toInt(teamTech),
    teamBiz: toInt(teamBiz),
    linkedin: sanitizeString(linkedin || linkedIn || "")
  };

  if (!clean.username || !password || !clean.name || !clean.email) {
    return res.status(400).json({ error: "Username, password, name and email are required." });
  }

  // very light username validation
  if (!/^[a-z0-9_\.]{3,30}$/.test(clean.username)) {
    return res.status(400).json({ error: "Username must be 3–30 chars, letters/numbers/._ only." });
  }

  const db = await loadDB();

  // Uniqueness checks
  const usernameTaken = db.users.some((u) => (u.username || "").toLowerCase() === clean.username);
  if (usernameTaken) return res.status(409).json({ error: "Username already taken." });

  const emailTaken = db.users.some((u) => (u.email || "").toLowerCase() === clean.email);
  if (emailTaken) return res.status(409).json({ error: "Email already in use." });

  const passwordHash = await bcrypt.hash(String(password), 10);

  const user = {
    id: nanoid(),
    ...clean,
    passwordHash,        // store hash, never plaintext
    createdAt: Date.now()
  };
  db.users.push(user);

  const session = createSession(clean.email);
  db.sessions.push(session);
  await saveDB(db);

  res.json({
    ok: true,
    userId: user.id,
    token: session.id,
    dashboardUrl: `/dashboard.html?token=${session.id}`
  });
});

// Login with email OR username + password
app.post("/api/login", async (req, res) => {
  const identifier = sanitizeString(req.body?.identifier || "");
  const password = String(req.body?.password || "");

  if (!identifier || !password) {
    return res.status(400).json({ error: "Identifier and password are required." });
  }

  const idLower = identifier.toLowerCase();
  const db = await loadDB();

  // find by email or username (case-insensitive)
  const user = db.users.find(
    (u) => (u.email && u.email.toLowerCase() === idLower) ||
           (u.username && u.username.toLowerCase() === idLower)
  );

  if (!user || !user.passwordHash) {
    return res.status(401).json({ error: "Invalid credentials." });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials." });

  const session = createSession(user.email);
  db.sessions.push(session);
  await saveDB(db);

  res.json({
    ok: true,
    token: session.id,
    dashboardUrl: `/dashboard.html?token=${session.id}`
  });
});
// Forgot password: create a one-time reset token and "send" link via console
app.post("/api/forgot-password", async (req, res) => {
    const identifier = sanitizeString(req.body?.identifier || "").toLowerCase();
    if (!identifier) return res.status(400).json({ ok: false, error: "Email or username is required." });
  
    const db = await loadDB();
    const user = db.users.find(
      (u) =>
        (u.email && u.email.toLowerCase() === identifier) ||
        (u.username && u.username.toLowerCase() === identifier)
    );
  
    // Always respond OK (don’t leak which emails exist).
    if (!user) return res.json({ ok: true, message: "If the account exists, a reset link was sent." });
  
    const token = nanoid();
    const now = Date.now();
    const expiresAt = now + 1000 * 60 * 30; // 30 minutes
  
    // Store token
    db.resetTokens.push({
      token,
      userId: user.id,
      email: user.email,
      createdAt: now,
      expiresAt
    });
    await saveDB(db);
  
    const resetUrl = `/reset.html?token=${encodeURIComponent(token)}`;
    // "Send email" — for MVP, we log it. In production, call SendGrid/Resend etc.
    console.log(`[Password Reset] Send to ${user.email}: http://localhost:3000${resetUrl}`);
  
    // For local dev, return the link so you can click it.
    return res.json({ ok: true, message: "If the account exists, a reset link was sent.", resetUrl });
  });
  
  // Reset password using the token
  app.post("/api/reset-password", async (req, res) => {
    const { token, password } = req.body || {};
    if (!token || !password) return res.status(400).json({ ok: false, error: "Token and new password are required." });
  
    const db = await loadDB();
    const entryIdx = db.resetTokens.findIndex((t) => t.token === token);
    if (entryIdx === -1) return res.status(400).json({ ok: false, error: "Invalid or expired token." });
  
    const entry = db.resetTokens[entryIdx];
    if (Date.now() > entry.expiresAt) {
      // expire and remove
      db.resetTokens.splice(entryIdx, 1);
      await saveDB(db);
      return res.status(400).json({ ok: false, error: "Invalid or expired token." });
    }
  
    const user = db.users.find((u) => u.id === entry.userId);
    if (!user) {
      db.resetTokens.splice(entryIdx, 1);
      await saveDB(db);
      return res.status(400).json({ ok: false, error: "Invalid or expired token." });
    }
  
    // Set new password
    const bcrypt = (await import("bcryptjs")).default; // safe import if not already at top
    user.passwordHash = await bcrypt.hash(String(password), 10);
  
    // Invalidate token
    db.resetTokens.splice(entryIdx, 1);
    await saveDB(db);
  
    return res.json({ ok: true, message: "Password has been reset. You can now log in." });
  });
  


// Current user
app.get("/api/me", authMiddleware, async (req, res) => {
  const db = await loadDB();
  const session = db.sessions.find((s) => s.id === req.token);
  if (!session) return res.status(401).json({ error: "Invalid token." });

  const user = db.users.find((u) => u.email === session.email);
  if (!user) return res.status(404).json({ error: "User not found." });

  res.json({ ok: true, user });
});
// Update my profile (owner only)
app.put("/api/profile", authMiddleware, async (req, res) => {
    const db = await loadDB();
  
    const session = db.sessions.find((s) => s.id === req.token);
    if (!session) return res.status(401).json({ error: "Invalid token." });
  
    const me = db.users.find((u) => u.email === session.email);
    if (!me) return res.status(404).json({ error: "User not found." });
  
    const {
      name, skills, role, industry, commitment, teamTech, teamBiz, linkedin
    } = req.body || {};
  
    // Only update provided fields (MVP simplicity)
    if (name !== undefined) me.name = sanitizeString(name);
    if (skills !== undefined) me.skills = sanitizeString(skills);
    if (role !== undefined) me.role = sanitizeString(role);
    if (industry !== undefined) me.industry = sanitizeString(industry);
    if (commitment !== undefined) me.commitment = sanitizeString(commitment);
    if (teamTech !== undefined) me.teamTech = toInt(teamTech);
    if (teamBiz !== undefined) me.teamBiz = toInt(teamBiz);
    if (linkedin !== undefined) me.linkedin = sanitizeString(linkedin);
  
    await saveDB(db);
    res.json({ ok: true, user: me });
  });
  
/* ---------------- Matches ---------------- */
app.get("/api/matches", authMiddleware, async (req, res) => {
  const db = await loadDB();
  const session = db.sessions.find((s) => s.id === req.token);
  if (!session) return res.status(401).json({ error: "Invalid token." });

  const me = db.users.find((u) => u.email === session.email);
  if (!me) return res.status(404).json({ error: "User not found." });

  const matches = db.users
    .filter((u) => u.email !== me.email)
    .map((u) => ({ user: u, score: matchScore(me, u) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map(({ user, score }) => ({
      id: user.id,
      name: user.name,
      skills: user.skills,
      role: user.role,
      industry: user.industry,
      commitment: user.commitment,
      score,
    }));

  res.json({ ok: true, matches });
});

// Read user (safe fields)
app.get("/api/users/:id", authMiddleware, async (req, res) => {
  const db = await loadDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "User not found." });

  res.json({
    ok: true,
    user: {
      id: user.id,
      name: user.name,
      skills: user.skills,
      role: user.role,
      industry: user.industry,
      commitment: user.commitment,
      linkedin: user.linkedin || ""
    },
  });
});

/* ---------------- Inbox APIs ---------------- */
// Conversation list (summaries)
app.get("/api/my-messages", authMiddleware, async (req, res) => {
  const db = await loadDB();
  const session = db.sessions.find((s) => s.id === req.token);
  if (!session) return res.status(401).json({ error: "Invalid token." });

  const me = db.users.find((u) => u.email === session.email);
  if (!me) return res.status(404).json({ error: "User not found." });

  const all = db.messages
    .filter((m) => m.fromUserId === me.id || m.toUserId === me.id)
    .sort((a, b) => a.createdAt - b.createdAt);

  const byPartner = new Map();
  for (const m of all) {
    const otherId = m.fromUserId === me.id ? m.toUserId : m.fromUserId;
    if (!byPartner.has(otherId)) byPartner.set(otherId, []);
    byPartner.get(otherId).push(m);
  }

  const conversations = [];
  for (const [otherId, msgs] of byPartner.entries()) {
    const other = db.users.find((u) => u.id === otherId);
    const last = msgs[msgs.length - 1];
    conversations.push({
      withUser: other
        ? {
            id: other.id,
            name: other.name,
            role: other.role,
            industry: other.industry,
            skills: other.skills,
          }
        : { id: otherId, name: "Unknown" },
      lastMessage: {
        fromUserId: last.fromUserId,
        toUserId: last.toUserId,
        subject: last.subject,
        body: last.body,
        createdAt: last.createdAt,
      },
      count: msgs.length,
    });
  }

  conversations.sort(
    (a, b) => b.lastMessage.createdAt - a.lastMessage.createdAt
  );

  res.json({ ok: true, conversations });
});

// Full thread with a specific user
app.get("/api/thread/:withUserId", authMiddleware, async (req, res) => {
  const db = await loadDB();
  const session = db.sessions.find((s) => s.id === req.token);
  if (!session) return res.status(401).json({ error: "Invalid token." });

  const me = db.users.find((u) => u.email === session.email);
  if (!me) return res.status(404).json({ error: "User not found." });

  const otherId = req.params.withUserId;
  const other = db.users.find((u) => u.id === otherId);
  if (!other) return res.status(404).json({ error: "Recipient not found." });

  const thread = db.messages
    .filter(
      (m) =>
        (m.fromUserId === me.id && m.toUserId === otherId) ||
        (m.fromUserId === otherId && m.toUserId === me.id)
    )
    .sort((a, b) => a.createdAt - b.createdAt);

  res.json({
    ok: true,
    me: { id: me.id, name: me.name },
    other: {
      id: other.id,
      name: other.name,
      role: other.role,
      industry: other.industry,
    },
    messages: thread,
  });
});

// Send message (mock)
app.post("/api/message", authMiddleware, async (req, res) => {
  const { toUserId, subject, body } = req.body || {};
  const db = await loadDB();

  const session = db.sessions.find((s) => s.id === req.token);
  if (!session) return res.status(401).json({ error: "Invalid token." });

  const fromUser = db.users.find((u) => u.email === session.email);
  if (!fromUser) return res.status(404).json({ error: "Sender not found." });

  const toUser = db.users.find((u) => u.id === toUserId);
  if (!toUser) return res.status(404).json({ error: "Recipient not found." });

  db.messages.push({
    id: nanoid(),
    fromUserId: fromUser.id,
    toUserId,
    subject: sanitizeString(subject),
    body: sanitizeString(body),
    createdAt: Date.now(),
  });

  await saveDB(db);
  res.json({ ok: true, message: "Message saved (email sending mocked)." });
});

/* ---------------- Admin: seed + stats ---------------- */
app.post("/api/seed-demo", async (req, res) => {
  const db = await loadDB();

  const alreadySeeded = db.users.some((u) =>
    u.email.endsWith("@demo.local")
  );
  if (alreadySeeded)
    return res.json({ ok: true, message: "Demo users already exist." });

  const demo = [
    { name: "Ava Chen", email: "ava@demo.local", skills: "react, node, design", role: "Technical Founder", industry: "AI", commitment: "Nights & Weekends" },
    { name: "Ben Ortiz", email: "ben@demo.local", skills: "go-to-market, sales, ops", role: "Business/GT-M Founder", industry: "AI", commitment: "Nights & Weekends" },
    { name: "Carla Singh", email: "carla@demo.local", skills: "python, ml, data", role: "Technical Founder", industry: "Health", commitment: "Full-time" },
    { name: "Dev Patel", email: "dev@demo.local", skills: "fintech, partnerships", role: "Business/GT-M Founder", industry: "Fintech", commitment: "Exploring" },
    { name: "Emma Li", email: "emma@demo.local", skills: "product, ux, research", role: "Product Founder", industry: "Consumer", commitment: "Full-time" },
    { name: "Felix Moore", email: "felix@demo.local", skills: "node, postgres, api", role: "Technical Founder", industry: "Fintech", commitment: "Nights & Weekends" },
    { name: "Grace Kim", email: "grace@demo.local", skills: "design, branding, ui", role: "Design Founder", industry: "Consumer", commitment: "Exploring" },
    { name: "Hank Zhao", email: "hank@demo.local", skills: "growth, paid ads", role: "Business/GT-M Founder", industry: "Consumer", commitment: "Full-time" },
    { name: "Iris Park", email: "iris@demo.local", skills: "python, ai, inference", role: "Technical Founder", industry: "AI", commitment: "Full-time" },
    { name: "Jamal Reed", email: "jamal@demo.local", skills: "security, devops, aws", role: "Technical Founder", industry: "DevTools", commitment: "Nights & Weekends" },
    { name: "Kira Novak", email: "kira@demo.local", skills: "healthcare ops, bizdev", role: "Business/GT-M Founder", industry: "Health", commitment: "Exploring" },
    { name: "Leo Rossi", email: "leo@demo.local", skills: "climate, supply chain", role: "Product Founder", industry: "Climate", commitment: "Full-time" }
  ];

  const now = Date.now();
  for (const u of demo) {
    db.users.push({ id: nanoid(), ...u, createdAt: now });
  }
  await saveDB(db);

  res.json({ ok: true, count: demo.length, message: "Seeded demo users." });
});

app.get("/api/stats", async (req, res) => {
  const db = await loadDB();
  res.json({
    ok: true,
    users: db.users.length,
    messages: db.messages.length,
    sessions: db.sessions.length,
  });
});

/* ---------------- Start ---------------- */
app.listen(PORT, () => {
  console.log(`MVP running at http://localhost:3000`);
});
