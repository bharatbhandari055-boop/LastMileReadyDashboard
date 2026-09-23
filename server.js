// LastMile Ready Dashboard — backend
//
// This server is the ONLY thing that talks to Firestore/Storage. The two
// frontend pages (public/index.html, public/admin.html) never touch Firebase
// directly — they call this API. That is a deliberate security choice: it
// keeps PINs and admin password hashes from ever being readable by a client
// with open Firestore rules.
//
// Collections (same names/shapes as the original Claude-artifact version):
//   profiles       — approved staff accounts (id = generated device/uid)
//   registrations  — pending/rejected/revoked signups
//   admins         — admin panel accounts (username + bcrypt hash)
//   content        — training content per persona
//   assessments    — one doc per persona, {questions:[{id,text}]}
//   submissions    — assessment answers per persona+uid
//   progress       — completion map per persona+uid

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("JWT_SECRET env var is required.");
  process.exit(1);
}

// ---------------- Firebase Admin init ----------------
// Expects the full service account JSON (from Firebase Console > Project
// Settings > Service Accounts > Generate new private key) in the
// FIREBASE_SERVICE_ACCOUNT env var, and the storage bucket name in
// FIREBASE_STORAGE_BUCKET (e.g. "your-project.appspot.com").
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || "{}");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET
});
const db = admin.firestore();
const bucket = admin.storage().bucket();

const PERSONAS = ["Scanner", "Team Leader", "Hub Manager and above", "City Lead", "Regional Manager"];
const slug = p => String(p).replace(/[^a-zA-Z0-9]/g, "_");

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });

// ---------------- Admin auth middleware ----------------
function requireAdmin(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "not_authenticated" });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "not_authenticated" });
  }
}

// =========================================================
// STAFF-FACING API
// =========================================================

// Register (pending admin approval)
app.post("/api/register", async (req, res) => {
  try {
    const { uid, name, phone, email, hub, city, role, pin } = req.body || {};
    if (!uid || !name || !phone || !email || !hub || !city || !role) {
      return res.status(400).json({ error: "missing_fields" });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "invalid_email" });
    if (!/^\d{7,15}$/.test(String(phone).replace(/[\s\-+]/g, ""))) return res.status(400).json({ error: "invalid_phone" });
    if (!/^\d{4}$/.test(String(pin))) return res.status(400).json({ error: "invalid_pin" });
    const data = {
      uid, name, phone: phone.toLowerCase(), email: email.toLowerCase(),
      hub, city, role, pin, status: "pending", submittedAt: Date.now()
    };
    await db.doc("registrations/" + uid).set(data);
    res.json(data);
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// Get this device's registration status (for the pending/rejected/revoked screens)
app.get("/api/registration/:uid", async (req, res) => {
  try {
    const snap = await db.doc("registrations/" + req.params.uid).get();
    if (!snap.exists) return res.json({ exists: false });
    res.json({ exists: true, data: snap.data() });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// Get this device's approved profile (persisted-login recognition)
app.get("/api/profile/:uid", async (req, res) => {
  try {
    const snap = await db.doc("profiles/" + req.params.uid).get();
    if (!snap.exists || snap.data().status !== "approved") return res.json({ exists: false });
    const { pin, ...safe } = snap.data();
    res.json({ exists: true, data: safe });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// PIN login (shared/kiosk devices) — the ONLY place a PIN is ever checked.
app.post("/api/staff-login", async (req, res) => {
  try {
    const idVal = String(req.body.id || "").trim().toLowerCase();
    const pin = String(req.body.pin || "").trim();
    if (!idVal || !/^\d{4}$/.test(pin)) return res.status(400).json({ error: "invalid_input" });
    let match = await findApprovedProfileByPin("phone", idVal, pin);
    if (!match) match = await findApprovedProfileByPin("email", idVal, pin);
    if (!match) return res.status(404).json({ error: "no_match" });
    const { pin: _drop, ...safe } = match.data;
    res.json({ id: match.id, data: safe });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
async function findApprovedProfileByPin(field, value, pin) {
  const snap = await db.collection("profiles").where(field, "==", value).limit(5).get();
  const hit = snap.docs.find(d => { const p = d.data(); return p.status === "approved" && p.pin === pin; });
  return hit ? { id: hit.id, data: hit.data() } : null;
}

// Content
app.get("/api/content", async (req, res) => {
  try {
    const persona = req.query.persona;
    const snap = await db.collection("content").where("persona", "==", persona).orderBy("createdAt", "asc").get();
    res.json(snap.docs.map(d => ({ id: d.id, data: d.data() })));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// Progress
app.get("/api/progress", async (req, res) => {
  try {
    const { persona, uid } = req.query;
    const snap = await db.doc("progress/" + slug(persona) + "_" + uid).get();
    res.json({ completed: (snap.exists && snap.data().completed) || {} });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/progress", async (req, res) => {
  try {
    const { persona, uid, contentId } = req.body || {};
    if (!persona || !uid || !contentId) return res.status(400).json({ error: "missing_fields" });
    const ref = db.doc("progress/" + slug(persona) + "_" + uid);
    const snap = await ref.get();
    const completed = (snap.exists && snap.data().completed) || {};
    if (!completed[contentId]) {
      completed[contentId] = true;
      await ref.set({ persona, uid, completed, updatedAt: Date.now() });
    }
    res.json({ completed });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// Assessment
app.get("/api/assessment", async (req, res) => {
  try {
    const persona = req.query.persona;
    const snap = await db.doc("assessments/" + slug(persona)).get();
    res.json({ questions: (snap.exists && snap.data().questions) || [] });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.get("/api/submission", async (req, res) => {
  try {
    const { persona, uid } = req.query;
    const snap = await db.doc("submissions/" + slug(persona) + "_" + uid).get();
    if (!snap.exists) return res.json({ exists: false });
    res.json({ exists: true, data: snap.data() });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/submission", async (req, res) => {
  try {
    const { persona, uid, answers } = req.body || {};
    if (!persona || !uid) return res.status(400).json({ error: "missing_fields" });
    await db.doc("submissions/" + slug(persona) + "_" + uid).set({ persona, uid, answers: answers || {}, submittedAt: Date.now() });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// =========================================================
// ADMIN API
// =========================================================

app.get("/api/admin/has-admin", async (req, res) => {
  try {
    const snap = await db.collection("admins").limit(1).get();
    res.json({ hasAdmin: !snap.empty });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.post("/api/admin/setup", async (req, res) => {
  try {
    const existing = await db.collection("admins").limit(1).get();
    if (!existing.empty) return res.status(409).json({ error: "admin_already_exists" });
    const uname = String(req.body.username || "").trim().toLowerCase();
    const pass = String(req.body.password || "");
    if (!uname || pass.length < 6) return res.status(400).json({ error: "invalid_input" });
    const passHash = await bcrypt.hash(pass, 10);
    const ref = await db.collection("admins").add({ username: uname, passHash, createdAt: Date.now() });
    const token = jwt.sign({ id: ref.id, username: uname }, JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, username: uname });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const uname = String(req.body.username || "").trim().toLowerCase();
    const pass = String(req.body.password || "");
    const snap = await db.collection("admins").where("username", "==", uname).limit(1).get();
    if (snap.empty) return res.status(401).json({ error: "invalid_credentials" });
    const doc = snap.docs[0];
    const ok = await bcrypt.compare(pass, doc.data().passHash);
    if (!ok) return res.status(401).json({ error: "invalid_credentials" });
    const token = jwt.sign({ id: doc.id, username: uname }, JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, username: uname });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.use("/api/admin", requireAdmin); // everything below requires a valid admin token

app.get("/api/admin/admins", async (req, res) => {
  try {
    const snap = await db.collection("admins").limit(50).get();
    res.json(snap.docs.map(d => ({ id: d.id, username: d.data().username })));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/admins", async (req, res) => {
  try {
    const uname = String(req.body.username || "").trim().toLowerCase();
    const pass = String(req.body.password || "");
    if (!uname || pass.length < 6) return res.status(400).json({ error: "invalid_input" });
    const exists = await db.collection("admins").where("username", "==", uname).limit(1).get();
    if (!exists.empty) return res.status(409).json({ error: "username_taken" });
    const passHash = await bcrypt.hash(pass, 10);
    await db.collection("admins").add({ username: uname, passHash, createdAt: Date.now() });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/registrations", async (req, res) => {
  try {
    const snap = await db.collection("registrations").where("status", "==", "pending").limit(100).get();
    res.json(snap.docs.map(d => ({ id: d.id, data: d.data() })));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/registrations/:uid/approve", async (req, res) => {
  try {
    const uid = req.params.uid;
    const roles = Array.isArray(req.body.roles) ? req.body.roles : [];
    if (roles.length === 0) return res.status(400).json({ error: "no_roles" });
    const regSnap = await db.doc("registrations/" + uid).get();
    if (!regSnap.exists) return res.status(404).json({ error: "not_found" });
    const r = regSnap.data();
    const approvedProfile = { name: r.name, phone: r.phone, email: r.email, hub: r.hub, city: r.city, pin: r.pin || "", roles, status: "approved", approvedAt: Date.now() };
    await db.doc("profiles/" + uid).set(approvedProfile);
    await db.doc("registrations/" + uid).update({ status: "approved" });
    const { pin, ...safe } = approvedProfile;
    res.json({ ok: true, profile: safe });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/registrations/:uid/reject", async (req, res) => {
  try {
    const note = String(req.body.note || "");
    await db.doc("registrations/" + req.params.uid).update({ status: "rejected", note });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/users", async (req, res) => {
  try {
    const snap = await db.collection("profiles").limit(200).get();
    const rows = snap.docs.filter(d => d.data().status === "approved").map(d => {
      const { pin, ...safe } = d.data();
      return { id: d.id, data: safe };
    });
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/users/:id/roles", async (req, res) => {
  try {
    const roles = Array.isArray(req.body.roles) ? req.body.roles : [];
    if (roles.length === 0) return res.status(400).json({ error: "no_roles" });
    await db.doc("profiles/" + req.params.id).update({ roles, updatedAt: Date.now() });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/users/:id/reset-pin", async (req, res) => {
  try {
    const newPin = String(Math.floor(1000 + Math.random() * 9000));
    await db.doc("profiles/" + req.params.id).update({ pin: newPin });
    const snap = await db.doc("profiles/" + req.params.id).get();
    res.json({ pin: newPin, name: snap.data().name, email: snap.data().email });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.delete("/api/admin/users/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const snap = await db.doc("profiles/" + id).get();
    const name = snap.exists ? snap.data().name : "";
    await db.doc("profiles/" + id).delete();
    const regSnap = await db.doc("registrations/" + id).get();
    if (regSnap.exists) await db.doc("registrations/" + id).update({ status: "revoked" });
    res.json({ ok: true, name });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/content", async (req, res) => {
  try {
    const persona = req.query.persona;
    const snap = await db.collection("content").where("persona", "==", persona).orderBy("createdAt", "asc").get();
    res.json(snap.docs.map(d => ({ id: d.id, data: d.data() })));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/content", async (req, res) => {
  try {
    const data = req.body || {};
    data.createdAt = data.createdAt || Date.now();
    const ref = await db.collection("content").add(data);
    res.json({ id: ref.id });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.put("/api/admin/content/:id", async (req, res) => {
  try {
    await db.collection("content").doc(req.params.id).set(req.body || {});
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.delete("/api/admin/content/:id", async (req, res) => {
  try {
    await db.collection("content").doc(req.params.id).delete();
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// File upload (video/PDF/PPT for content items) -> Firebase Storage
app.post("/api/admin/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "no_file" });
    const ext = (req.file.originalname.split(".").pop() || "bin").toLowerCase();
    const fname = "content/" + Date.now() + "_" + crypto.randomBytes(6).toString("hex") + "." + ext;
    const fileRef = bucket.file(fname);
    await fileRef.save(req.file.buffer, { contentType: req.file.mimetype });
    await fileRef.makePublic();
    res.json({ url: `https://storage.googleapis.com/${bucket.name}/${fname}` });
  } catch (e) { console.error(e); res.status(500).json({ error: "upload_failed" }); }
});

app.get("/api/admin/questions", async (req, res) => {
  try {
    const persona = req.query.persona;
    const snap = await db.doc("assessments/" + slug(persona)).get();
    res.json({ questions: (snap.exists && snap.data().questions) || [] });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/questions", async (req, res) => {
  try {
    const { persona, text } = req.body || {};
    if (!persona || !text) return res.status(400).json({ error: "missing_fields" });
    const ref = db.doc("assessments/" + slug(persona));
    const snap = await ref.get();
    const qs = (snap.exists && snap.data().questions) || [];
    qs.push({ id: crypto.randomUUID(), text });
    await ref.set({ questions: qs });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.delete("/api/admin/questions/:persona/:qid", async (req, res) => {
  try {
    const ref = db.doc("assessments/" + slug(req.params.persona));
    const snap = await ref.get();
    const qs = ((snap.exists && snap.data().questions) || []).filter(x => x.id !== req.params.qid);
    await ref.set({ questions: qs });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/submissions", async (req, res) => {
  try {
    const persona = req.query.persona;
    const snap = await db.collection("submissions").where("persona", "==", persona).limit(50).get();
    res.json(snap.docs.map(d => d.data()));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// =========================================================
// Static frontend
// =========================================================
app.use(express.static(path.join(__dirname, "public")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log("LastMile Ready dashboard listening on " + PORT));
