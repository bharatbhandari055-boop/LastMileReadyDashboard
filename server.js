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
const RIDER_PERSONA = "Hope on Wheels"; // the rider role/persona name, used as the content/progress/assessment key
const slug = p => String(p).replace(/[^a-zA-Z0-9]/g, "_");
function ok(err) { if (err) throw err; }
function last4(phone) { const digits = String(phone).replace(/\D/g, ""); return digits.slice(-4).padStart(4, "0"); }

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
// STAFF-FACING API
// =========================================================

app.post("/api/register", async (req, res) => {
  try {
    const { uid, name, phone, email, hub, city, role, pin } = req.body || {};
    if (!uid || !name || !phone || !email || !hub || !city || !role) return res.status(400).json({ error: "missing_fields" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "invalid_email" });
    if (!/^\d{7,15}$/.test(String(phone).replace(/[\s\-+]/g, ""))) return res.status(400).json({ error: "invalid_phone" });
    if (!/^\d{4}$/.test(String(pin))) return res.status(400).json({ error: "invalid_pin" });
    const data = { uid, name, phone: phone.toLowerCase(), email: email.toLowerCase(), hub, city, role, pin, status: "pending", category: "User", submitted_at: Date.now() };
    const { error } = await sb.from("registrations").upsert(data);
    ok(error);
    res.json(toRegPayload(data));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// Rider ("Hope on Wheels") self-registration — auto-approved immediately,
// no admin review step. PIN defaults to the last 4 digits of the phone
// number entered; the rider is forced to change it on first successful
// login (see must_change_pin) before they can view any content.
app.post("/api/register-rider", async (req, res) => {
  try {
    const { uid, name, phone, hub, city } = req.body || {};
    if (!uid || !phone || !hub || !city) return res.status(400).json({ error: "missing_fields" });
    const cleanPhone = String(phone).replace(/[\s\-+]/g, "").toLowerCase();
    if (!/^\d{7,15}$/.test(cleanPhone)) return res.status(400).json({ error: "invalid_phone" });
    // If this phone is already onboarded (e.g. admin bulk-uploaded them, or
    // they registered before on another device), don't create a duplicate —
    // just hand back their existing record so this device can sign in as them.
    const { data: existing } = await sb.from("profiles").select("*").eq("phone", cleanPhone).maybeSingle();
    if (existing) return res.json({ id: existing.id, data: toProfilePayload(existing, true) });
    const profile = {
      id: uid, name: name || null, phone: cleanPhone, email: null, hub, city,
      pin: last4(cleanPhone), roles: [RIDER_PERSONA], status: "approved",
      category: "Hope on Wheels", must_change_pin: true, approved_at: Date.now(), updated_at: Date.now()
    };
    const { error } = await sb.from("profiles").upsert(profile);
    ok(error);
    res.json({ id: uid, data: toProfilePayload(profile, true) });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// Self-service PIN change — required before a rider (or anyone flagged
// must_change_pin) can view content. Not admin-gated: the caller just
// needs to already be signed in as `uid` on the client.
app.post("/api/change-pin", async (req, res) => {
  try {
    const { uid, newPin } = req.body || {};
    if (!uid || !/^\d{4}$/.test(String(newPin))) return res.status(400).json({ error: "invalid_input" });
    const { data, error } = await sb.from("profiles").update({ pin: String(newPin), must_change_pin: false, updated_at: Date.now() }).eq("id", uid).select().maybeSingle();
    ok(error);
    if (!data) return res.status(404).json({ error: "not_found" });
    res.json({ ok: true, data: toProfilePayload(data, true) });
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
    const { data, error } = await sb.from("assessments").select("*").eq("persona", req.query.persona).maybeSingle();
    ok(error);
    res.json({ questions: (data && data.questions) || [] });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.get("/api/submission", async (req, res) => {
  try {
    const id = slug(req.query.persona) + "_" + req.query.uid;
    const { data, error } = await sb.from("submissions").select("*").eq("id", id).maybeSingle();
    ok(error);
    if (!data) return res.json({ exists: false });
    res.json({ exists: true, data: { persona: data.persona, uid: data.uid, answers: data.answers, submittedAt: data.submitted_at } });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/submission", async (req, res) => {
  try {
    const { persona, uid, answers } = req.body || {};
    if (!persona || !uid) return res.status(400).json({ error: "missing_fields" });
    const id = slug(persona) + "_" + uid;
    const ans = answers || {};

    // Score only the mcq questions that carry a "correct" answer.
    const { data: aRow } = await sb.from("assessments").select("*").eq("persona", persona).maybeSingle();
    const questions = (aRow && aRow.questions) || [];
    const passScore = (aRow && aRow.pass_score != null) ? Number(aRow.pass_score) : 80;
    const mcqs = questions.filter(q => q.type === "mcq" && q.correct);
    let score = null, passed = null;
    if (mcqs.length > 0) {
      const numCorrect = mcqs.filter(q => ans[q.id] === q.correct).length;
      score = Math.round((numCorrect / mcqs.length) * 100);
      passed = score >= passScore;
    }

    const { error } = await sb.from("submissions").upsert({ id, persona, uid, answers: ans, score, passed, submitted_at: Date.now() });
    ok(error);

    // Fail -> full re-earn: wipe this user's content-watch progress for the
    // topic so they must re-watch/re-read everything before re-attempting.
    if (passed === false) {
      const progId = slug(persona) + "_" + uid;
      const { error: perr } = await sb.from("progress").upsert({ id: progId, persona, uid, completed: {}, updated_at: Date.now() });
      ok(perr);
    }

    res.json({ ok: true, score, passed });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

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

// Bulk rider onboarding. Body: { rows: [{phone, name, hub, city}, ...] }
// (client parses the uploaded sheet and posts plain rows — no file storage
// needed here). For each row, matched by phone:
//  - new phone  -> create approved profile, pin = last 4 of phone, must_change_pin = true
//  - existing phone -> update name/hub/city only; PIN and must_change_pin are left
//    untouched so re-running a corrected sheet never resets an active rider's login
app.post("/api/admin/bulk-riders", async (req, res) => {
  try {
    const rows = Array.isArray(req.body.rows) ? req.body.rows : [];
    if (rows.length === 0) return res.status(400).json({ error: "no_rows" });
    const results = [];
    for (const row of rows) {
      const rawPhone = String(row.phone || "").trim();
      const cleanPhone = rawPhone.replace(/[\s\-+]/g, "").toLowerCase();
      const hub = String(row.hub || "").trim();
      const city = String(row.city || "").trim();
      const name = row.name ? String(row.name).trim() : null;
      if (!/^\d{7,15}$/.test(cleanPhone) || !hub || !city) {
        results.push({ phone: rawPhone, status: "error", reason: "invalid_phone_or_missing_hub_city" });
        continue;
      }
      try {
        const { data: existing } = await sb.from("profiles").select("id,phone").eq("phone", cleanPhone).maybeSingle();
        if (existing) {
          const { error } = await sb.from("profiles").update({ name, hub, city, updated_at: Date.now() }).eq("id", existing.id);
          ok(error);
          results.push({ phone: cleanPhone, status: "updated", id: existing.id });
        } else {
          const id = crypto.randomUUID();
          const pin = last4(cleanPhone);
          const profile = { id, name, phone: cleanPhone, email: null, hub, city, pin, roles: [RIDER_PERSONA], status: "approved", category: "Hope on Wheels", must_change_pin: true, approved_at: Date.now(), updated_at: Date.now() };
          const { error } = await sb.from("profiles").insert(profile);
          ok(error);
          results.push({ phone: cleanPhone, status: "created", id, pin });
        }
      } catch (rowErr) {
        results.push({ phone: cleanPhone, status: "error", reason: "server_error" });
      }
    }
    res.json({ results });
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
    const row = { persona: b.persona, type: b.type, title: b.title, description: b.description, url: b.url, required_minutes: b.requiredMinutes, created_at: b.createdAt || Date.now() };
    const { data, error } = await sb.from("content").insert(row).select().single();
    ok(error);
    res.json({ id: data.id });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.put("/api/admin/content/:id", async (req, res) => {
  try {
    const b = req.body || {};
    const row = { persona: b.persona, type: b.type, title: b.title, description: b.description, url: b.url, required_minutes: b.requiredMinutes, created_at: b.createdAt || Date.now() };
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

app.get("/api/admin/questions", async (req, res) => {
  try {
    const { data, error } = await sb.from("assessments").select("*").eq("persona", req.query.persona).maybeSingle();
    ok(error);
    res.json({ questions: (data && data.questions) || [], passScore: (data && data.pass_score != null) ? data.pass_score : 80 });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.post("/api/admin/questions", async (req, res) => {
  try {
    const { persona, text, type, options, correct } = req.body || {};
    if (!persona || !text) return res.status(400).json({ error: "missing_fields" });
    const q = { id: crypto.randomUUID(), text };
    if (type === "mcq") {
      const opts = (Array.isArray(options) ? options : []).map(o => String(o).trim()).filter(Boolean);
      if (opts.length < 2) return res.status(400).json({ error: "need_at_least_2_options" });
      if (!correct || !opts.includes(String(correct))) return res.status(400).json({ error: "correct_answer_must_match_an_option" });
      q.type = "mcq";
      q.options = opts;
      q.correct = String(correct);
    }
    const { data: existing } = await sb.from("assessments").select("*").eq("persona", persona).maybeSingle();
    const qs = (existing && existing.questions) || [];
    qs.push(q);
    const passScore = (existing && existing.pass_score != null) ? existing.pass_score : 80;
    const { error } = await sb.from("assessments").upsert({ persona, questions: qs, pass_score: passScore });
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
// Set the % of mcq questions a persona's staff/riders must get right to pass.
app.post("/api/admin/assessment/:persona/pass-score", async (req, res) => {
  try {
    const passScore = Number(req.body.passScore);
    if (!(passScore > 0 && passScore <= 100)) return res.status(400).json({ error: "invalid_pass_score" });
    const { data: existing } = await sb.from("assessments").select("*").eq("persona", req.params.persona).maybeSingle();
    const qs = (existing && existing.questions) || [];
    const { error } = await sb.from("assessments").upsert({ persona: req.params.persona, questions: qs, pass_score: passScore });
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});
app.delete("/api/admin/questions/:persona/:qid", async (req, res) => {
  try {
    const { data: existing } = await sb.from("assessments").select("*").eq("persona", req.params.persona).maybeSingle();
    const qs = ((existing && existing.questions) || []).filter(x => x.id !== req.params.qid);
    const { error } = await sb.from("assessments").upsert({ persona: req.params.persona, questions: qs });
    ok(error);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

app.get("/api/admin/submissions", async (req, res) => {
  try {
    const { data, error } = await sb.from("submissions").select("*").eq("persona", req.query.persona).limit(50);
    ok(error);
    res.json(data.map(s => ({ uid: s.uid, answers: s.answers, submittedAt: s.submitted_at })));
  } catch (e) { console.error(e); res.status(500).json({ error: "server_error" }); }
});

// =========================================================
// Row -> API payload helpers (snake_case DB columns -> camelCase JSON,
// matching exactly what the frontend already expects)
// =========================================================
function toRegPayload(r) {
  return { uid: r.uid, name: r.name, phone: r.phone, email: r.email, hub: r.hub, city: r.city, role: r.role, pin: r.pin, status: r.status, note: r.note, category: r.category || "User", submittedAt: r.submitted_at };
}
function toProfilePayload(p, dropPin) {
  const out = { name: p.name, phone: p.phone, email: p.email, hub: p.hub, city: p.city, roles: p.roles || [], status: p.status, category: p.category || "User", mustChangePin: !!p.must_change_pin, pin: p.pin };
  if (dropPin) delete out.pin;
  return out;
}
function rowToContent(c) {
  return { id: c.id, data: { persona: c.persona, type: c.type, title: c.title, description: c.description, url: c.url, requiredMinutes: c.required_minutes, createdAt: c.created_at } };
}

// =========================================================
// Static frontend
// =========================================================
app.use(express.static(path.join(__dirname, "public")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log("LastMile Ready dashboard listening on " + PORT));
