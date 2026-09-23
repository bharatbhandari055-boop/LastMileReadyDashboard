# LastMile Ready — Dashboard (Render + Firebase build)

This is the Render-deployable version of your training dashboard. It keeps
the same UI, the same PIN/admin login flow, the same registration/approval
process, the same video-watch-time and dwell-timer completion gating, and
the same admin panel — all of it is the same code, just moved from
Claude's `claude.use("db"/"user"/"assets"/"mcp")` calls to a real backend
(Express + Firebase, deployed on Render).

## What actually changed (read this)

Everything else is untouched, but these things had no equivalent outside
Claude's artifact runtime and needed a real replacement:

1. **"Recognized automatically on your own phone"** used to come from
   Claude's org identity. It's now a random ID generated once per browser
   and stored in `localStorage` — so on your own phone you'll still be
   recognized automatically on future visits (until you clear browser
   data), same as before. On shared/kiosk devices, PIN login works exactly
   as it did.
2. **The admin panel's extra "org account must have edit rights" gate is
   gone** — there's no "org" outside Claude to check. The panel is now
   protected purely by the username/password login your code already had
   as a second layer, which is unchanged.
3. **"Search organization members by name" (to pre-assign a role before
   someone registers) is removed.** That searched Claude's org member
   directory, which doesn't exist here. Admins still approve/manage anyone
   who registers themselves, same as before — this only removes the
   pre-assign-before-registration shortcut.
4. **Admin passwords are now hashed with bcrypt on the server** instead of
   unsalted SHA-256 in the browser. Same login screen, same experience —
   just stronger storage.
5. **"📧 Email Login Info" currently shows the PIN in a toast** for the
   admin to copy/share, instead of emailing it — no email service is
   configured yet. Wire up real SMTP or the Gmail API in
   `emailLoginDetails`/`showPinToShare` (client) and add a `/api/admin/email`
   route (server) whenever you're ready; that's a self-contained addition.

## 1. Create a Firebase project

1. Go to https://console.firebase.google.com → **Add project** → give it a
   name (e.g. `lastmile-ready`) → finish the wizard.
2. In the left sidebar: **Build → Firestore Database → Create database** →
   start in **production mode** → pick a region close to your users.
3. In the left sidebar: **Build → Storage → Get started** → same region →
   accept the default rules for now (the server uses a service account, so
   client-side storage rules don't matter for this app).
4. **Project settings (gear icon) → Service accounts → Generate new private
   key.** This downloads a JSON file — keep it secret, you'll paste its
   contents into Render as an environment variable (never commit it to
   git).
5. Still in Project settings, note your **Storage bucket** name (usually
   `<project-id>.appspot.com`) — General tab.
6. Deploy the Firestore rules in `firestore.rules` (deny-all client
   access, since only the server touches the database):
   ```
   npm install -g firebase-tools
   firebase login
   firebase init firestore   # pick your project, keep the existing rules file
   firebase deploy --only firestore:rules
   ```

## 2. Configure environment variables

Copy `.env.example` → `.env` for local testing, or set these directly as
**Environment Variables** in Render (Settings tab of your Render service):

| Variable | Value |
|---|---|
| `FIREBASE_SERVICE_ACCOUNT` | Entire contents of the service-account JSON file, as one line |
| `FIREBASE_STORAGE_BUCKET` | e.g. `your-project-id.appspot.com` |
| `JWT_SECRET` | A long random string (see `.env.example` for how to generate one) |

## 3. Deploy to Render

This is a **Node web service**, so on Render:

- **Root Directory**: leave blank if this folder is your repo root (it has
  `package.json` at the top level — that's what was missing before).
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- Add the three environment variables above under the service's
  **Environment** tab.
- Deploy. Once it's live, visit `/` for the staff dashboard and `/admin`
  for the admin panel.

## 4. Local testing (optional)

```
npm install
npm start
```
Visit `http://localhost:3000` and `http://localhost:3000/admin`.

## File map

```
server.js         — Express API + static file server (the only thing that touches Firestore/Storage)
package.json       — dependencies + start script
firestore.rules    — deny-all client rules (server bypasses these via the service account)
public/index.html  — staff dashboard (unchanged UI/logic, now calls the API instead of claude.use)
public/admin.html  — admin panel (same)
.env.example       — required environment variables
```
