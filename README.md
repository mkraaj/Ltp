# MKRAAJLTP

Hindi-first SSC + UPSC learning platform MVP with a performance-based study agent.

## What is working

- Responsive dark/light student dashboard with Hindi UI and keyboard-friendly controls.
- Separate student and admin login; admin routes enforce the `admin` role server-side.
- SQLite persistence using Node's built-in `node:sqlite` (Node 22.5+; verified on Node v26.3.1).
- Original practice bank: 21 SSC and 12 UPSC questions. These are clearly marked as original practice, not previous-year papers.
- Mock-test engine:
  - server-owned timer/deadline
  - next/previous navigation and question palette
  - mark for review
  - answer autosave and resume
  - SSC/UPSC positive and negative marking
  - idempotent submit and server-authoritative scoring
- Detailed results: total, attempted, correct, incorrect, unattempted, score, accuracy, time, rank/percentile when available, per-question explanations, subject/topic signals and revision recommendations.
- Explainable local study planner based on submitted attempts; optional server-only OpenAI-compatible provider for the Study Agent.
- Bank-based personalized practice is intentionally labelled as bank practice, not AI-generated content.
- Student question practice, bookmarks, personal notes, notifications, leaderboard and protected material downloads.
- Admin CMS UI for material drafts/uploads, publish/unpublish/delete and mock-test building; secured APIs for question creation/import, current-affairs publishing and AI draft review.
- Premium flags and entitlement table are ready for a future subscription/payment layer; premium content is blocked by default without an entitlement.

## Run locally

```bash
cp .env.example .env
# edit .env if needed
npm run check
npm test
npm start
```

Open <http://localhost:3000>.

The database is created at `data/app.sqlite` and uploads are stored privately under `storage/uploads/`. Both are ignored by git. Do not commit `.env`, database files, uploads, passwords or API keys.

## Create an admin account

There are no bundled demo credentials. Create the first admin explicitly:

```bash
ADMIN_EMAIL='admin@example.com' \\
ADMIN_PASSWORD='use-a-long-unique-password' \\
ADMIN_NAME='MKRAAJLTP Admin' \\
npm run bootstrap-admin
```

The bootstrap script requires a valid email and a password between 12 and 256 characters. It refuses duplicate emails and stores only a scrypt-derived password hash/salt.

A student can register from the UI. Never send a password or token in chat or commit it to a repository.

## Configuration

Copy `.env.example` to `.env`:

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP port, default `3000` |
| `DB_PATH` | SQLite file, default `data/app.sqlite` |
| `DATA_DIR` | Data directory |
| `UPLOAD_DIR` | Private upload directory |
| `SESSION_DAYS` | Session lifetime, clamped to 1–30 days |
| `NODE_ENV` | Set `production` to add the `Secure` cookie flag |
| `ORIGIN` | Exact browser origin for mutation checks; use HTTPS in production |
| `AI_API_URL` | Optional OpenAI-compatible chat endpoint |
| `AI_API_KEY` | Server-only provider key; never expose it to browser code |
| `AI_MODEL` | Provider model name |

Without `AI_API_URL` and `AI_API_KEY`, the app uses the local explainable planner and bank-based practice. It does not claim those responses are live AI-generated.

## Important content note

Current Affairs starts empty on purpose: live facts must be uploaded by an authorized admin with a reputable source URL. The admin API rejects a current-affairs item without a source URL. The seeded question bank is original practice and does not pretend to be SSC/UPSC previous-year content. PDF/image uploads are stored and protected, but automatic PDF text extraction is not included yet; the admin can provide an excerpt for optional AI draft generation.

## Checks run

```bash
npm run check
node --check public/app.js
npm test
```

The integration tests cover registration/session cookies, role separation, owner-scoped attempts, invalid answer rejection, autosave, idempotent submission, result explanations, unpublished admin content and upload validation.

A local smoke flow was also run against a temporary SQLite database: root/health, catalog, student registration, dashboard, test start, answer save, submit, detailed result, admin bootstrap and protected admin stats all returned successfully.

## Architecture

- `public/index.html`, `public/styles.css`, `public/app.js`: dependency-free responsive web UI.
- `server.js`: native HTTP routing, auth, authorization, test engine, upload validation and JSON API.
- `database.js`: SQLite initialization, schema seed and scrypt helpers.
- `database/schema.sql`: normalized tables for users, students, admins, exams, subjects, topics, courses, materials, questions, tests, test questions, attempts, answers, results, current affairs, bookmarks, notes, notifications, drafts, progress, sessions and practice answers.
- `scripts/bootstrap-admin.js`: explicit admin provisioning.
- `test/backend.test.js`: Node integration/security tests.

The current rate-limit and session state are single-process. For a multi-instance deployment, move sessions/rate limits to a shared store and put the app behind HTTPS/reverse-proxy protections. Payment gateway, entitlement management and distributed deployment are intentionally future layers.
