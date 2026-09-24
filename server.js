// LastMile Ready Dashboard — backend (Supabase edition)
//
// Same design as the Firebase version: this server is the ONLY thing that
// talks to the database/storage. The frontend (public/index.html,
// public/admin.html) only ever calls this server's /api/... routes — so
// those two files are 100% unchanged from the Firebase build.
//
// Uses the Supabase SERVICE ROLE key, which bypasses Row Level Security
// entirely. Every table has RLS enabled with no policies (see schema.sql),
// so the public anon key — and therefore the browser — can't read or
// write anything directly. Never ship the service role key to the client.

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");
const path = require("path");
const crypto = require("crypto");
const XLSX = require("xlsx");

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error("JWT_SECRET env var is required."); process.exit(1); }

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY env vars are required.");
  process.exit(1);
}
const STORAGE_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || "content-files";

const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

const PERSONAS = ["Scanner", "Team Leader", "Hub Manager and above", "City Lead", "Regional Manager"];
const slug = p => String(p).replace(/[^a-zA-Z0-9]/g, "_");
function ok(err) { if (err) throw err; }

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });

function requireAdmin(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "not_authenticated" });
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { return res.status(401).json({ error: "not_authenticated" }); }
}

// =========================================================
// Email (for content-assignment notifications) — NOT WIRED IN YET.
// Kept here ready to use: once you want assignment emails to actually
// send, install nodemailer (`npm install nodemailer`), uncomment the
// require below, set SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/SMTP_FROM
// on the server, and call sendAssignmentEmail(...) from the assign
// endpoints below (the call sites are marked with a comment).
// =========================================================
// const nodemailer = require("nodemailer");
let mailer = null;
// if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
//   mailer = nodemailer.createTransport({
//     host: process.env.SMTP_HOST,
//     port: Number(process.env.SMTP_PORT || 587),
//     secure: Number(process.env.SMTP_PORT) === 465,
//     auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
//   });
// }
const MAIL_FROM = process.env.SMTP_FROM || process.env.SMTP_USER || "no-reply@lastmileready.app";

async function sendAssignmentEmail(toEmail, name, items) {
  const list = items.map(c => `- ${c.title} (${c.type})`).join("\n");
  const subject = "New training content assigned to you — LastMile Ready";
  const text = `Hi ${name},\n\nYou've been assigned new training content:\n\n${list}\n\nLog in to your LastMile Ready dashboard to view it.\n\n— LastMile Ready`;
  if (!mailer) {
    console.log("[email skipped - SMTP not configured] To:", toEmail, "\n", text);
    return false;
  }
  await mailer.sendMail({ from: MAIL_FROM, to: toEmail, subject, text });
  return true;
}

// =========================================================
// STAFF-FACING API
// =========================================================

app.post("/api/register", async (req, res) => {
  try {
    const { uid, name, phone, email, hub, city, role, pin } = req.body || {};
    if (!uid || !name || !phone || !email || !hub || !city || !role) return res.status(400).json({ error: "missing_fields" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "invalid_email" });
    if (!/^\d{7,15}$/.test(String(phone).replace(/[\s\-+]/g, ""))) return res.status(400).json({ error: "invalid_phone" });
    if (!/^\d{4}$/.test(String(pin))) return res.status(400).json({ error: "invalid_pin" });
    const data = { uid, name, phone: phone.toLowerCase(), email: email.toLowerCase(), hub, city, role, pin, status: "pending", submitted_at: Date.now() };
    const { error } = await sb.from("registrations").upsert(data);
    ok(error);
    res.json(toRegPayload(data));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/registration/:uid", async (req, res) => {
  try {
    const { data, error } = await sb.from("registrations").select("*").eq("uid", req.params.uid).maybeSingle();
    ok(error);
    if (!data) return res.json({ exists: false });
    res.json({ exists: true, data: toRegPayload(data) });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/profile/:uid", async (req, res) => {
  try {
    const { data, error } = await sb.from("profiles").select("*").eq("id", req.params.uid).maybeSingle();
    ok(error);
    if (!data || data.status !== "approved") return res.json({ exists: false });
    res.json({ exists: true, data: toProfilePayload(data, true) });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.post("/api/staff-login", async (req, res) => {
  try {
    const idVal = String(req.body.id || "").trim().toLowerCase();
    const pin = String(req.body.pin || "").trim();
    if (!idVal || !/^\d{4}$/.test(pin)) return res.status(400).json({ error: "invalid_input" });
    let match = await findApprovedProfileByPin("phone", idVal, pin);
    if (!match) match = await findApprovedProfileByPin("email", idVal, pin);
    if (!match) return res.status(404).json({ error: "no_match" });
    res.json({ id: match.id, data: toProfilePayload(match, true) });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
async function findApprovedProfileByPin(field, value, pin) {
  const { data, error } = await sb.from("profiles").select("*").eq(field, value).eq("status", "approved").eq("pin", pin).limit(1);
  ok(error);
  return (data && data[0]) || null;
}

app.get("/api/content", async (req, res) => {
  try {
    const { data, error } = await sb.from("content").select("*").eq("persona", req.query.persona).order("created_at", { ascending: true });
    ok(error);
    res.json(data.map(rowToContent));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// Content assigned directly to this user (independent of persona/role),
// via the admin's "Assign Content to Users" panel or bulk upload.
app.get("/api/assigned-content", async (req, res) => {
  try {
    const uid = req.query.uid;
    if (!uid) return res.status(400).json({ error: "missing_uid" });
    const { data: assigns, error: e1 } = await sb.from("assignments").select("*").eq("uid", uid);
    ok(e1);
    if (!assigns || assigns.length === 0) return res.json([]);
    const ids = assigns.map(a => a.content_id);
    const { data: rows, error: e2 } = await sb.from("content").select("*").in("id", ids);
    ok(e2);
    const dueById = {};
    assigns.forEach(a => { dueById[a.content_id] = a.due_date || null; });
    res.json(rows.map(c => { const item = rowToContent(c); item.data.dueDate = dueById[c.id] || null; return item; }));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/progress", async (req, res) => {
  try {
    const id = slug(req.query.persona) + "_" + req.query.uid;
    const { data, error } = await sb.from("progress").select("*").eq("id", id).maybeSingle();
    ok(error);
    res.json({ completed: (data && data.completed) || {} });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/progress", async (req, res) => {
  try {
    const { persona, uid, contentId } = req.body || {};
    if (!persona || !uid || !contentId) return res.status(400).json({ error: "missing_fields" });
    const id = slug(persona) + "_" + uid;
    const { data: existing } = await sb.from("progress").select("*").eq("id", id).maybeSingle();
    const completed = (existing && existing.completed) || {};
    if (!completed[contentId]) {
      completed[contentId] = true;
      const { error } = await sb.from("progress").upsert({ id, persona, uid, completed, updated_at: Date.now() });
      ok(error);
    }
    res.json({ completed });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/assessment", async (req, res) => {
  try {
    const topic = req.query.topic || "General";
    const { data, error } = await sb.from("assessments").select("*").eq("persona", req.query.persona).eq("topic", topic).maybeSingle();
    ok(error);
    // Staff-facing: never send correctAnswer to the browser, or the
    // answer key would sit in plain sight in the network tab.
    const questions = ((data && data.questions) || []).map(stripCorrectAnswer);
    res.json({ questions });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
function stripCorrectAnswer(q) {
  const { correctAnswer, ...rest } = q;
  return rest;
}
app.get("/api/submission", async (req, res) => {
  try {
    const topic = req.query.topic || "General";
    const { data, error } = await sb.from("submissions").select("*").eq("persona", req.query.persona).eq("topic", topic).eq("uid", req.query.uid).maybeSingle();
    ok(error);
    if (!data) return res.json({ exists: false });
    res.json({ exists: true, data: { persona: data.persona, topic: data.topic, uid: data.uid, answers: data.answers, score: data.score || null, submittedAt: data.submitted_at } });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/submission", async (req, res) => {
  try {
    const { persona, uid, answers } = req.body || {};
    const topic = req.body.topic || "General";
    if (!persona || !uid) return res.status(400).json({ error: "missing_fields" });
    // Grade against the server's own copy of the questions — the client
    // never sees correctAnswer, so there's nothing for it to fake here.
    const score = await scoreAnswers(persona, topic, answers || {});
    const { error } = await sb.from("submissions").upsert({ persona, topic, uid, answers: answers || {}, score, submitted_at: Date.now() });
    ok(error);
    res.json({ ok: true, score });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
// Score covers only mcq questions that have a correctAnswer set — free
// text isn't auto-gradable. Returns null (no score line shown) if the
// topic has no scorable questions at all.
async function scoreAnswers(persona, topic, answers) {
  const { data } = await sb.from("assessments").select("*").eq("persona", persona).eq("topic", topic).maybeSingle();
  const questions = (data && data.questions) || [];
  const mcqs = questions.filter(q => q.type === "mcq" && q.correctAnswer);
  if (mcqs.length === 0) return null;
  let correct = 0;
  mcqs.forEach(q => { if (answers[q.id] === q.correctAnswer) correct++; });
  return { correct, total: mcqs.length };
}

// =========================================================
// ADMIN API
// =========================================================

app.get("/api/admin/has-admin", async (req, res) => {
  try {
    const { count, error } = await sb.from("admins").select("*", { count: "exact", head: true });
    ok(error);
    res.json({ hasAdmin: count > 0 });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.post("/api/admin/setup", async (req, res) => {
  try {
    const { count } = await sb.from("admins").select("*", { count: "exact", head: true });
    if (count > 0) return res.status(409).json({ error: "admin_already_exists" });
    const uname = String(req.body.username || "").trim().toLowerCase();
    const pass = String(req.body.password || "");
    if (!uname || pass.length < 6) return res.status(400).json({ error: "invalid_input" });
    const passHash = await bcrypt.hash(pass, 10);
    const { data, error } = await sb.from("admins").insert({ username: uname, pass_hash: passHash, created_at: Date.now() }).select().single();
    ok(error);
    const token = jwt.sign({ id: data.id, username: uname }, JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, username: uname });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const uname = String(req.body.username || "").trim().toLowerCase();
    const pass = String(req.body.password || "");
    const { data, error } = await sb.from("admins").select("*").eq("username", uname).maybeSingle();
    ok(error);
    if (!data) return res.status(401).json({ error: "invalid_credentials" });
    const match = await bcrypt.compare(pass, data.pass_hash);
    if (!match) return res.status(401).json({ error: "invalid_credentials" });
    const token = jwt.sign({ id: data.id, username: uname }, JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, username: uname });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.use("/api/admin", requireAdmin);

app.get("/api/admin/admins", async (req, res) => {
  try {
    const { data, error } = await sb.from("admins").select("id, username").limit(50);
    ok(error);
    res.json(data);
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/admins", async (req, res) => {
  try {
    const uname = String(req.body.username || "").trim().toLowerCase();
    const pass = String(req.body.password || "");
    if (!uname || pass.length < 6) return res.status(400).json({ error: "invalid_input" });
    const { data: existing } = await sb.from("admins").select("id").eq("username", uname).maybeSingle();
    if (existing) return res.status(409).json({ error: "username_taken" });
    const passHash = await bcrypt.hash(pass, 10);
    const { error } = await sb.from("admins").insert({ username: uname, pass_hash: passHash, created_at: Date.now() });
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/registrations", async (req, res) => {
  try {
    const { data, error } = await sb.from("registrations").select("*").eq("status", "pending").limit(100);
    ok(error);
    res.json(data.map(r => ({ id: r.uid, data: toRegPayload(r) })));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/registrations/:uid/approve", async (req, res) => {
  try {
    const uid = req.params.uid;
    const roles = Array.isArray(req.body.roles) ? req.body.roles : [];
    if (roles.length === 0) return res.status(400).json({ error: "no_roles" });
    const { data: r, error: e1 } = await sb.from("registrations").select("*").eq("uid", uid).maybeSingle();
    ok(e1);
    if (!r) return res.status(404).json({ error: "not_found" });
    const approvedProfile = { id: uid, name: r.name, phone: r.phone, email: r.email, hub: r.hub, city: r.city, pin: r.pin || "", roles, status: "approved", approved_at: Date.now() };
    const { error: e2 } = await sb.from("profiles").upsert(approvedProfile);
    ok(e2);
    const { error: e3 } = await sb.from("registrations").update({ status: "approved" }).eq("uid", uid);
    ok(e3);
    res.json({ ok: true, profile: toProfilePayload(approvedProfile, true) });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/registrations/:uid/reject", async (req, res) => {
  try {
    const note = String(req.body.note || "");
    const { error } = await sb.from("registrations").update({ status: "rejected", note }).eq("uid", req.params.uid);
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/users", async (req, res) => {
  try {
    const { data, error } = await sb.from("profiles").select("*").eq("status", "approved").limit(200);
    ok(error);
    res.json(data.map(p => ({ id: p.id, data: toProfilePayload(p, true) })));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/users/:id/roles", async (req, res) => {
  try {
    const roles = Array.isArray(req.body.roles) ? req.body.roles : [];
    if (roles.length === 0) return res.status(400).json({ error: "no_roles" });
    const { error } = await sb.from("profiles").update({ roles, updated_at: Date.now() }).eq("id", req.params.id);
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/users/:id/reset-pin", async (req, res) => {
  try {
    const newPin = String(Math.floor(1000 + Math.random() * 9000));
    const { data, error } = await sb.from("profiles").update({ pin: newPin }).eq("id", req.params.id).select().single();
    ok(error);
    res.json({ pin: newPin, name: data.name, email: data.email });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.delete("/api/admin/users/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const { data: snap } = await sb.from("profiles").select("name").eq("id", id).maybeSingle();
    const { error: e1 } = await sb.from("profiles").delete().eq("id", id);
    ok(e1);
    const { data: reg } = await sb.from("registrations").select("uid").eq("uid", id).maybeSingle();
    if (reg) { const { error: e2 } = await sb.from("registrations").update({ status: "revoked" }).eq("uid", id); ok(e2); }
    res.json({ ok: true, name: snap && snap.name });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/content", async (req, res) => {
  try {
    const { data, error } = await sb.from("content").select("*").eq("persona", req.query.persona).order("created_at", { ascending: true });
    ok(error);
    res.json(data.map(rowToContent));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/content", async (req, res) => {
  try {
    const b = req.body || {};
    const row = { persona: b.persona, topic: b.topic || "General", type: b.type, title: b.title, description: b.description, url: b.url, required_minutes: b.requiredMinutes, created_at: b.createdAt || Date.now() };
    const { data, error } = await sb.from("content").insert(row).select().single();
    ok(error);
    res.json({ id: data.id });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.put("/api/admin/content/:id", async (req, res) => {
  try {
    const b = req.body || {};
    const row = { persona: b.persona, topic: b.topic || "General", type: b.type, title: b.title, description: b.description, url: b.url, required_minutes: b.requiredMinutes, created_at: b.createdAt || Date.now() };
    const { error } = await sb.from("content").update(row).eq("id", req.params.id);
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.delete("/api/admin/content/:id", async (req, res) => {
  try {
    const { error } = await sb.from("content").delete().eq("id", req.params.id);
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// File upload -> Supabase Storage
app.post("/api/admin/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "no_file" });
    const ext = (req.file.originalname.split(".").pop() || "bin").toLowerCase();
    const fname = "content/" + Date.now() + "_" + crypto.randomBytes(6).toString("hex") + "." + ext;
    const { error } = await sb.storage.from(STORAGE_BUCKET).upload(fname, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
    ok(error);
    const { data } = sb.storage.from(STORAGE_BUCKET).getPublicUrl(fname);
    res.json({ url: data.publicUrl });
  } catch (e) { console.error(e); res.status(500).json({ error: "upload_failed" }); }
});

// Distinct topics that currently have content under a persona, in the
// order that content was first created — lets the admin panel offer a
// topic switcher without a separate topics table.
app.get("/api/admin/topics", async (req, res) => {
  try {
    const { data, error } = await sb.from("content").select("topic, created_at").eq("persona", req.query.persona).order("created_at", { ascending: true });
    ok(error);
    const seen = [];
    (data || []).forEach(r => { const t = (r.topic || "General").trim() || "General"; if (!seen.includes(t)) seen.push(t); });
    if (!seen.includes("General")) seen.push("General");
    res.json({ topics: seen });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/questions", async (req, res) => {
  try {
    const topic = req.query.topic || "General";
    const { data, error } = await sb.from("assessments").select("*").eq("persona", req.query.persona).eq("topic", topic).maybeSingle();
    ok(error);
    res.json({ questions: (data && data.questions) || [] });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/questions", async (req, res) => {
  try {
    const { persona, text, type, options, correctAnswer } = req.body || {};
    const topic = req.body.topic || "General";
    if (!persona || !text) return res.status(400).json({ error: "missing_fields" });
    const q = { id: crypto.randomUUID(), text };
    if (type === "mcq") {
      const opts = (Array.isArray(options) ? options : []).map(o => String(o).trim()).filter(Boolean);
      if (opts.length < 2) return res.status(400).json({ error: "need_at_least_2_options" });
      const correct = String(correctAnswer || "").trim();
      if (!correct || !opts.includes(correct)) return res.status(400).json({ error: "correct_answer_required" });
      q.type = "mcq";
      q.options = opts;
      q.correctAnswer = correct;
    }
    const { data: existing } = await sb.from("assessments").select("*").eq("persona", persona).eq("topic", topic).maybeSingle();
    const qs = (existing && existing.questions) || [];
    qs.push(q);
    const { error } = await sb.from("assessments").upsert({ persona, topic, questions: qs });
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.delete("/api/admin/questions/:qid", async (req, res) => {
  try {
    const persona = req.query.persona;
    const topic = req.query.topic || "General";
    const { data: existing } = await sb.from("assessments").select("*").eq("persona", persona).eq("topic", topic).maybeSingle();
    const qs = ((existing && existing.questions) || []).filter(x => x.id !== req.params.qid);
    const { error } = await sb.from("assessments").upsert({ persona, topic, questions: qs });
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/submissions", async (req, res) => {
  try {
    const topic = req.query.topic || "General";
    const { data, error } = await sb.from("submissions").select("*").eq("persona", req.query.persona).eq("topic", topic).limit(50);
    ok(error);
    res.json(data.map(s => ({ uid: s.uid, answers: s.answers, score: s.score || null, submittedAt: s.submitted_at })));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// =========================================================
// ADMIN: Assign content to specific users (manual)
// =========================================================
app.post("/api/admin/assign", async (req, res) => {
  try {
    const contentIds = Array.isArray(req.body.contentIds) ? req.body.contentIds : [];
    const uids = Array.isArray(req.body.uids) ? req.body.uids : [];
    const dueDate = req.body.dueDate ? Number(req.body.dueDate) : null; // ms timestamp, optional

    if (contentIds.length === 0 || uids.length === 0) return res.status(400).json({ error: "missing_fields" });

    const { data: contentRows, error: e1 } = await sb.from("content").select("*").in("id", contentIds);
    ok(e1);
    if (!contentRows || contentRows.length === 0) return res.status(404).json({ error: "content_not_found" });

    const { data: profileRows, error: e2 } = await sb.from("profiles").select("*").in("id", uids).eq("status", "approved");
    ok(e2);
    if (!profileRows || profileRows.length === 0) return res.status(404).json({ error: "users_not_found" });

    const rows = [];
    for (const profile of profileRows) {
      for (const c of contentRows) {
        rows.push({ content_id: c.id, uid: profile.id, assigned_at: Date.now(), due_date: dueDate });
      }
    }
    const { error: e3 } = await sb.from("assignments").upsert(rows, { onConflict: "content_id,uid" });
    ok(e3);

    // To enable email notifications later: uncomment below (and set up
    // SMTP as noted at the top of this file).
    // for (const profile of profileRows) {
    //   await sendAssignmentEmail(profile.email, profile.name, contentRows.map(rowToContent).map(c => c.data));
    // }

    res.json({ ok: true, assignedUsers: profileRows.map(p => ({ id: p.id, name: p.name })), assignedContent: contentRows.length });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// =========================================================
// ADMIN: Bulk-assign from a spreadsheet upload
// Expected columns (case-insensitive, flexible naming):
// "User Name"/"Name", "Phone", "Topic / Module"/"Topic",
// "Completion Date" (optional — blank means no deadline).
// =========================================================
app.post("/api/admin/assign-bulk-upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "no_file" });
    const wb = XLSX.read(req.file.buffer, { type: "buffer", cellDates: true });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(sheet, { defval: "" });

    const results = { total: rows.length, assigned: 0, skipped: [] };
    const { data: profiles } = await sb.from("profiles").select("*").eq("status", "approved");
    const { data: allContent } = await sb.from("content").select("*");
    const normPhone = s => String(s || "").replace(/[\s\-+]/g, "").toLowerCase();

    for (const [i, row] of rows.entries()) {
      const get = (...keys) => {
        for (const k of keys) {
          const found = Object.keys(row).find(rk => rk.trim().toLowerCase() === k);
          if (found && String(row[found]).trim() !== "") return row[found];
        }
        return "";
      };
      const name = String(get("user name", "name") || "");
      const phone = String(get("phone", "phone number", "mobile", "mobile number") || "");
      const topic = String(get("topic / module", "topic/module", "topic", "module") || "");
      const dateVal = get("completion date", "due date", "deadline");

      if (!phone || !topic) { results.skipped.push({ row: i + 2, name, phone, topic, reason: "Missing phone or topic" }); continue; }

      const profile = (profiles || []).find(p => normPhone(p.phone) === normPhone(phone));
      if (!profile) { results.skipped.push({ row: i + 2, name, phone, topic, reason: "No approved user found with this phone" }); continue; }

      const roles = profile.roles || [];
      const matches = (allContent || []).filter(c => roles.includes(c.persona) && String(c.topic || "General").trim().toLowerCase() === topic.trim().toLowerCase());
      if (matches.length === 0) { results.skipped.push({ row: i + 2, name, phone, topic, reason: "No content found for this topic under the user's role(s)" }); continue; }

      let dueDate = null;
      if (dateVal) {
        const parsed = new Date(dateVal);
        if (!isNaN(parsed.getTime())) dueDate = parsed.getTime();
        else { results.skipped.push({ row: i + 2, name, phone, topic, reason: "Could not parse completion date: '" + dateVal + "'" }); continue; }
      }

      const assignRows = matches.map(c => ({ content_id: c.id, uid: profile.id, assigned_at: Date.now(), due_date: dueDate }));
      const { error } = await sb.from("assignments").upsert(assignRows, { onConflict: "content_id,uid" });
      if (error) { results.skipped.push({ row: i + 2, name, phone, topic, reason: "Database error: " + error.message }); continue; }
      results.assigned++;

      // To enable email notifications later: uncomment below.
      // try { await sendAssignmentEmail(profile.email, profile.name, matches.map(c => rowToContent(c).data)); } catch (mailErr) { console.error(mailErr); }
    }

    res.json(results);
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/assignments", async (req, res) => {
  try {
    let q = sb.from("assignments").select("*").order("assigned_at", { ascending: false }).limit(200);
    if (req.query.uid) q = q.eq("uid", req.query.uid);
    const { data, error } = await q;
    ok(error);
    res.json(data);
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// =========================================================
// ADMIN: CSV export — one row per person. Approved users get training
// completion counts (overall + per-role breakdown); pending/rejected/
// revoked registrations are listed too so the file covers everyone.
// =========================================================
app.get("/api/admin/export-csv", async (req, res) => {
  try {
    const { data: profiles, error: e1 } = await sb.from("profiles").select("*").limit(2000);
    ok(e1);
    const { data: regs, error: e2 } = await sb.from("registrations").select("*").limit(2000);
    ok(e2);

    const contentCache = {}, progressCache = {};
    async function contentFor(persona) {
      if (!contentCache[persona]) {
        const { data } = await sb.from("content").select("id").eq("persona", persona);
        contentCache[persona] = data || [];
      }
      return contentCache[persona];
    }
    async function progressFor(persona, uid) {
      const key = persona + "::" + uid;
      if (!(key in progressCache)) {
        const id = slug(persona) + "_" + uid;
        const { data } = await sb.from("progress").select("completed").eq("id", id).maybeSingle();
        progressCache[key] = (data && data.completed) || {};
      }
      return progressCache[key];
    }

    const header = ["Name","Phone","Email","Hub","City","Roles","Status","Per-Role Breakdown","Total Modules","Completed Modules","Pending Modules","Completion %"];
    const rows = [];

    for (const p of (profiles || [])) {
      const roles = p.roles || [];
      let total = 0, completed = 0;
      const roleParts = [];
      for (const persona of roles) {
        const items = await contentFor(persona);
        const done = await progressFor(persona, p.id);
        const roleDone = items.filter(i => done[i.id]).length;
        total += items.length;
        completed += roleDone;
        roleParts.push(`${persona}: ${roleDone}/${items.length} done`);
      }
      const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
      rows.push([p.name, p.phone, p.email, p.hub, p.city, roles.join("; "), "Active", roleParts.join(" | "), total, completed, total - completed, pct + "%"]);
    }
    for (const r of (regs || [])) {
      if ((profiles || []).some(p => p.id === r.uid)) continue;
      rows.push([r.name, r.phone, r.email, r.hub, r.city, r.role, cap(r.status), "", "", "", "", ""]);
    }

    const csv = [header, ...rows].map(r => r.map(csvEscape).join(",")).join("\r\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="lastmile_ready_users_${Date.now()}.csv"`);
    res.send(csv);
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
function csvEscape(v) { const s = v == null ? "" : String(v); return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

// =========================================================
// Row -> API payload helpers (snake_case DB columns -> camelCase JSON,
// matching exactly what the frontend already expects)
// =========================================================
function toRegPayload(r) {
  return { uid: r.uid, name: r.name, phone: r.phone, email: r.email, hub: r.hub, city: r.city, role: r.role, pin: r.pin, status: r.status, note: r.note, submittedAt: r.submitted_at };
}
function toProfilePayload(p, dropPin) {
  const out = { name: p.name, phone: p.phone, email: p.email, hub: p.hub, city: p.city, roles: p.roles || [], status: p.status, pin: p.pin };
  if (dropPin) delete out.pin;
  return out;
}
function rowToContent(c) {
  return { id: c.id, data: { persona: c.persona, topic: c.topic || "General", type: c.type, title: c.title, description: c.description, url: c.url, requiredMinutes: c.required_minutes, createdAt: c.created_at } };
}

// =========================================================
// Static frontend
// =========================================================
app.use(express.static(path.join(__dirname, "public")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log("LastMile Ready dashboard listening on " + PORT));
