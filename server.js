const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');
const {
  DB_FILE, id, now, hashPassword, verifyPassword, parseJson, transaction, openDatabase, closeDatabase
} = require('./database');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'storage', 'uploads');
const SESSION_DAYS = Math.max(1, Math.min(30, Number(process.env.SESSION_DAYS || 7)));
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;
const MAX_BODY = 5 * 1024 * 1024;
const MAX_FILE = 5 * 1024 * 1024;
const AI_CONFIGURED = Boolean(process.env.AI_API_URL && process.env.AI_API_KEY);
const buckets = new Map();

function clean(value, max = 500) { return String(value ?? '').trim().replace(/[<>]/g, '').slice(0, max); }
function cleanEmail(value) { return clean(value, 180).toLowerCase(); }
function asInt(value, fallback = NaN) { const n = Number(value); return Number.isInteger(n) ? n : fallback; }
function bool(value) { return value === true || value === 1 || value === '1' || value === 'true'; }
function unique(values) { return [...new Set(values)]; }
function jsonValue(value, fallback) { return parseJson(value, fallback); }
function dbRows(db, sql, ...params) { return db.prepare(sql).all(...params); }
function dbRow(db, sql, ...params) { return db.prepare(sql).get(...params); }
function dbRun(db, sql, ...params) { return db.prepare(sql).run(...params); }
function errorMessage(error) { return error?.message || ''; }

function publicUser(user) {
  if (!user) return null;
  return { id: user.id, name: user.name, email: user.email, role: user.role, exam: user.exam };
}
function parseCookies(req) {
  const result = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const at = part.indexOf('=');
    if (at < 0) continue;
    try { result[part.slice(0, at).trim()] = decodeURIComponent(part.slice(at + 1).trim()); } catch {}
  }
  return result;
}
function tokenHash(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function isProduction() { return process.env.NODE_ENV === 'production'; }
function cookieHeader(token, maxAge = Math.floor(SESSION_MS / 1000)) {
  return `student_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${isProduction() ? '; Secure' : ''}`;
}
function sessionToken(db, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const timestamp = now();
  transaction(db, () => {
    dbRun(db, 'DELETE FROM sessions WHERE expires_at <= ?', timestamp);
    dbRun(db, 'INSERT INTO sessions (id,user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?,?)', id('session'), userId, tokenHash(token), new Date(Date.now() + SESSION_MS).toISOString(), timestamp);
  });
  return token;
}
function currentUser(db, req) {
  const token = parseCookies(req).student_session;
  if (!token) return null;
  const session = dbRow(db, 'SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?', tokenHash(token), now());
  if (!session) return null;
  return dbRow(db, 'SELECT * FROM users WHERE id = ? AND active = 1', session.user_id) || null;
}
function removeSession(db, req) {
  const token = parseCookies(req).student_session;
  if (token) dbRun(db, 'DELETE FROM sessions WHERE token_hash = ?', tokenHash(token));
}

function sendJson(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  res.end(body);
}
function fail(res, status, message, details) { return sendJson(res, status, { error: message, ...(details ? { details } : {}) }); }
function requireUser(db, req, res, role) {
  const user = currentUser(db, req);
  if (!user) { fail(res, 401, 'कृपया पहले login करें।'); return null; }
  if (role && user.role !== role) { fail(res, 403, 'इस section के लिए आपके पास अनुमति नहीं है।'); return null; }
  return user;
}
function checkOrigin(req, res) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return true;
  const origin = req.headers.origin;
  if (!origin) {
    if (req.headers['sec-fetch-site'] === 'cross-site') { fail(res, 403, 'सुरक्षित origin से request भेजें।'); return false; }
    return true; // Non-browser local scripts have no Origin; browser mutations are checked below.
  }
  const expected = process.env.ORIGIN || `http://${req.headers.host || 'localhost'}`;
  let hostname;
  try { hostname = new URL(expected).hostname; } catch { return false; }
  if ((!process.env.ORIGIN && !['localhost','127.0.0.1','[::1]'].includes(hostname)) || origin !== expected) { fail(res, 403, 'सुरक्षित origin से request भेजें।'); return false; }
  return true;
}
function rateLimit(req, res, bucket, max) {
  const key = `${req.socket.remoteAddress || 'local'}:${bucket}`;
  const current = Date.now();
  let item = buckets.get(key);
  if (!item || current - item.start >= 60_000) item = { start: current, count: 0 };
  item.count += 1; buckets.set(key, item);
  if (buckets.size > 2000) for (const [k, value] of buckets) if (current - value.start > 120_000) buckets.delete(k);
  while (buckets.size > 2000) buckets.delete(buckets.keys().next().value);
  if (item.count > max) { fail(res, 429, 'बहुत अधिक requests। थोड़ी देर बाद फिर कोशिश करें।'); return false; }
  return true;
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length'] || 0);
    if (declared > MAX_BODY) return reject(Object.assign(new Error('BODY_TOO_LARGE'), { code: 'BODY_TOO_LARGE' }));
    const chunks = []; let total = 0; let rejected = false;
    req.on('data', (chunk) => {
      if (rejected) return;
      total += chunk.length;
      if (total > MAX_BODY) { rejected = true; reject(Object.assign(new Error('BODY_TOO_LARGE'), { code: 'BODY_TOO_LARGE' })); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (rejected) return;
      if (!chunks.length) return resolve({});
      const raw = Buffer.concat(chunks).toString('utf8');
      const type = String(req.headers['content-type'] || '');
      if (!type.includes('application/json')) return resolve(Object.fromEntries(new URLSearchParams(raw)));
      try { resolve(JSON.parse(raw)); } catch { reject(Object.assign(new Error('INVALID_JSON'), { code: 'INVALID_JSON' })); }
    });
    req.on('error', reject);
  });
}
function safeUrl(value) {
  const text = clean(value, 500);
  if (!text) return '';
  try { const parsed = new URL(text); return ['http:', 'https:'].includes(parsed.protocol) ? text : ''; } catch { return ''; }
}
function arrayText(value, maxItems = 20, maxLength = 300) {
  return Array.isArray(value) ? value.slice(0, maxItems).map((item) => clean(item, maxLength)).filter(Boolean) : [];
}
function examValue(value) { return value === 'UPSC' || value === 'SSC' ? value : null; }
function difficultyValue(value) { return ['Easy', 'Medium', 'Hard'].includes(value) ? value : null; }
function userEntitled(db, user, entitlement) {
  if (user.role === 'admin') return true;
  return Boolean(dbRow(db, 'SELECT 1 AS ok FROM user_entitlements WHERE user_id = ? AND entitlement = ? AND (expires_at IS NULL OR expires_at > ?)', user.id, entitlement, now()));
}

function materialView(row) {
  return {
    id: row.id, title: row.title, description: row.description, exam: row.exam, subject: row.subject,
    topic: row.topic, chapter: row.chapter, type: row.type, premium: Boolean(row.premium), published: Boolean(row.published),
    sourceUrl: row.source_url, fileName: row.file_name, fileAvailable: Boolean(row.file_path), createdAt: row.created_at
  };
}
function questionView(row) {
  return { id: row.id || row.question_id, exam: row.exam, subject: row.subject, topic: row.topic, difficulty: row.difficulty, year: row.year, type: row.type || 'MCQ', stem: row.stem, options: jsonValue(row.options_json, []), source: row.source || 'Original practice question' };
}
function adminQuestionView(row) {
  return { ...questionView(row), correctIndex: row.correct_index, explanation: row.explanation, source: row.source, published: Boolean(row.published), createdAt: row.created_at };
}
function testRow(db, idValue) { return dbRow(db, 'SELECT * FROM tests WHERE id = ?', idValue); }
function testQuestions(db, testId) {
  return dbRows(db, `SELECT q.*, tq.position FROM test_questions tq JOIN questions q ON q.id = tq.question_id WHERE tq.test_id = ? ORDER BY tq.position`, testId);
}
function testView(db, test, includeAnswers = false) {
  const questions = testQuestions(db, test.id).map((q) => includeAnswers ? adminQuestionView(q) : questionView(q));
  return { id: test.id, title: test.title, exam: test.exam, category: test.category, description: test.description,
    durationMinutes: test.duration_minutes, positiveMarking: test.positive_marking, negativeMarking: test.negative_marking,
    questionCount: questions.length, published: Boolean(test.published), questions };
}
function canSeeTest(user, test) { return Boolean(test && ((test.published && !test.owner_user_id) || (test.owner_user_id && test.owner_user_id === user.id) || (test.published && user.role === 'admin'))); }
function attemptData(db, attempt) {
  const answers = dbRows(db, 'SELECT question_id,answer_index,marked_review FROM answers WHERE attempt_id = ?', attempt.id);
  const answerMap = Object.fromEntries(answers.map((a) => [a.question_id, a.answer_index === null ? null : a.answer_index]));
  const review = answers.filter((a) => a.marked_review).map((a) => a.question_id);
  const test = testRow(db, attempt.test_id);
  const questions = dbRows(db, 'SELECT * FROM attempt_questions WHERE attempt_id = ? ORDER BY position', attempt.id).map((q) => questionView(q));
  return { attempt: { id: attempt.id, testId: attempt.test_id, status: attempt.status, startedAt: attempt.started_at, deadlineAt: attempt.deadline_at, answers: answerMap, review }, test: test ? { id: test.id, title: test.title, exam: test.exam, questions, durationMinutes: test.duration_minutes, positiveMarking: test.positive_marking, negativeMarking: test.negative_marking } : null, serverNow: now() };
}
function assertAnswerMap(db, attempt, supplied, review) {
  if (!supplied || typeof supplied !== 'object' || Array.isArray(supplied)) throw new Error('ANSWERS_OBJECT');
  const allowed = new Map(dbRows(db, 'SELECT question_id,options_json FROM attempt_questions WHERE attempt_id = ?', attempt.id).map((q) => [q.question_id, jsonValue(q.options_json, [])]));
  for (const [questionId, raw] of Object.entries(supplied)) {
    if (!allowed.has(questionId)) throw new Error('QUESTION_NOT_IN_ATTEMPT');
    if (raw === null || raw === '') continue;
    if (!Number.isInteger(raw) || raw < 0 || raw >= allowed.get(questionId).length) throw new Error('INVALID_ANSWER_INDEX');
  }
  const marked = review === undefined ? null : review;
  if (marked !== null && (!Array.isArray(marked) || marked.some((questionId) => !allowed.has(questionId)))) throw new Error('INVALID_REVIEW');
  return marked;
}

function submittedRows(db, userId) {
  return dbRows(db, `SELECT r.*, t.title AS test_title, t.exam AS exam FROM results r JOIN tests t ON t.id = r.test_id WHERE r.user_id = ? ORDER BY r.created_at DESC`, userId);
}
function metrics(db, userId) {
  const rows = dbRows(db, `SELECT r.*, aq.question_id, aq.subject, aq.topic, a.answer_index, aq.correct_index
    FROM results r JOIN attempt_questions aq ON aq.attempt_id = r.attempt_id
    LEFT JOIN answers a ON a.attempt_id = aq.attempt_id AND a.question_id = aq.question_id
    WHERE r.user_id = ?`, userId);
  const subjects = new Map(); const topics = new Map(); const mistakes = new Map();
  for (const row of rows) {
    const attempted = row.answer_index !== null && row.answer_index !== undefined;
    const correct = attempted && row.answer_index === row.correct_index;
    for (const [map, key, subject] of [[subjects, row.subject, row.subject], [topics, `${row.subject}\u0000${row.topic}`, row.topic]]) {
      const item = map.get(key) || { subject: row.subject, topic: map === topics ? subject : undefined, correct: 0, total: 0 };
      item.total += 1;
      if (correct) item.correct += 1;
      map.set(key, item);
    }
    if (attempted && !correct) mistakes.set(row.topic, (mistakes.get(row.topic) || 0) + 1);
  }
  const subjectList = [...subjects.values()].map((x) => ({ subject: x.subject, accuracy: x.total ? Math.round(x.correct / x.total * 100) : 0, total: x.total })).sort((a, b) => b.accuracy - a.accuracy);
  const topicList = [...topics.values()].map((x) => ({ topic: x.topic, subject: x.subject, accuracy: x.total ? Math.round(x.correct / x.total * 100) : 0, total: x.total })).sort((a, b) => a.accuracy - b.accuracy);
  const weakTopics = topicList.filter((x) => x.accuracy < 75).slice(0, 5).map((x) => x.topic);
  return { weakTopics, strongSubjects: subjectList.filter((x) => x.accuracy >= 75).slice(0, 4).map((x) => x.subject), subjects: subjectList, topics: topicList, repeatedMistakes: [...mistakes.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([topic, count]) => ({ topic, count })) };
}
function streak(db, userId) {
  const days = unique(dbRows(db, 'SELECT substr(created_at,1,10) AS day FROM results WHERE user_id = ? ORDER BY day DESC', userId).map((x) => x.day));
  if (!days.length) return 0;
  const current = new Date(`${days[0]}T00:00:00Z`); const today = new Date(); today.setUTCHours(0, 0, 0, 0);
  if ((today - current) / 86400000 > 1) return 0;
  let count = 1;
  for (let i = 1; i < days.length; i += 1) { const date = new Date(`${days[i]}T00:00:00Z`); if ((current - date) / 86400000 !== i) break; count += 1; }
  return count;
}
function stats(db, userId) {
  const row = dbRow(db, `SELECT COUNT(*) AS tests, COALESCE(SUM(attempted),0) AS solved, COALESCE(SUM(correct),0) AS correct,
    COALESCE(SUM(time_taken_seconds),0) AS seconds FROM results WHERE user_id = ?`, userId);
  return { testsCompleted: row.tests, questionsSolved: row.solved, accuracy: row.solved ? Math.round(row.correct / row.solved * 100) : 0, streak: streak(db, userId), studyMinutes: Math.ceil(row.seconds / 60) };
}
function rankFor(db, userId) {
  const list = dbRows(db, `SELECT u.id, u.name, COALESCE(SUM(r.score),0) AS score, COUNT(r.id) AS tests_completed,
    CASE WHEN COALESCE(SUM(r.attempted),0) = 0 THEN 0 ELSE ROUND(SUM(r.correct) * 100.0 / SUM(r.attempted)) END AS accuracy
    FROM users u LEFT JOIN results r ON r.user_id = u.id WHERE u.role = 'student' AND u.active = 1 GROUP BY u.id ORDER BY score DESC, accuracy DESC, u.created_at ASC`);
  const mineIndex = list.findIndex((x) => x.id === userId);
  if (mineIndex < 0 || Number(list[mineIndex].tests_completed) === 0) return null;
  return { rank: mineIndex + 1, percentile: list.length ? Math.max(1, Math.round((list.length - mineIndex) / list.length * 100)) : 1 };
}
function planFor(db, user) {
  const performance = metrics(db, user.id); const stat = stats(db, user.id);
  if (!stat.testsCompleted) return { headline: 'पहले छोटा assessment देकर शुरुआत करें।', reason: 'अभी submitted attempt नहीं है; पहले practice test दें ताकि plan आपके वास्तविक प्रदर्शन पर बने।', items: [{ time: '15 min', title: 'Initial assessment', detail: 'अपने exam का छोटा practice test पूरा करें।', kind: 'assessment' }, { time: '10 min', title: 'Mistake review', detail: 'हर उत्तर के बाद explanation पढ़ें।', kind: 'review' }], recommendations: ['पहले assessment के बाद यह plan आपके weak topics से बदलेगा।'], generatedBy: 'local performance rules' };
  const first = performance.weakTopics[0]; const second = performance.weakTopics[1];
  return { headline: stat.accuracy < 60 ? 'पहले accuracy मजबूत करें, फिर speed बढ़ाएँ।' : 'आपकी progress दिख रही है—अब weak topics को polish करें।', reason: first ? `आपके submitted attempts में ${first} की accuracy सबसे कम है।` : 'आपके submitted attempts में कोई स्पष्ट weak topic नहीं है; mixed practice जारी रखें।', items: [{ time: '25 min', title: first ? `${first} का concept revision` : 'Mixed concept revision', detail: 'Short notes पढ़ें और active recall करें।', kind: 'revision' }, { time: '20 min', title: second ? `${second} के practice questions` : 'Timed practice', detail: 'हर answer के बाद explanation पढ़ें; guesswork से बचें।', kind: 'practice' }, { time: '10 min', title: 'Mistake review', detail: 'गलतियों को concept, calculation, reading या time-pressure कारण से tag करें।', kind: 'reflection' }], recommendations: first ? [`अगले 3 दिनों में ${first} revise करें।`, second ? `${second} में timed practice करें।` : 'Mixed timed practice करें।'] : ['Mixed practice और नियमित review जारी रखें।'], generatedBy: 'local performance rules' };
}
function dashboard(db, user) {
  return { user: publicUser(user), stats: stats(db, user.id), progress: metrics(db, user.id), plan: planFor(db, user), notifications: dbRows(db, `SELECT id,title,body,type,is_read AS read,created_at AS createdAt FROM notifications WHERE user_id = ? OR user_id IS NULL ORDER BY created_at DESC LIMIT 10`, user.id), aiConfigured: AI_CONFIGURED, rank: rankFor(db, user.id) };
}
function publicResultRow(row) { return { id: row.id, attemptId: row.attempt_id, testTitle: row.test_title, totalQuestions: row.total_questions, attempted: row.attempted, correct: row.correct, incorrect: row.incorrect, unattempted: row.unattempted, score: row.score, maxScore: row.max_score, accuracy: row.accuracy, timeTaken: row.time_taken_seconds, createdAt: row.created_at }; }
function detailedResult(db, row, user) {
  const questions = dbRows(db, `SELECT aq.*, a.answer_index, a.marked_review FROM attempt_questions aq LEFT JOIN answers a ON a.attempt_id = aq.attempt_id AND a.question_id = aq.question_id WHERE aq.attempt_id = ? ORDER BY aq.position`, row.attempt_id).map((q) => ({ question: { id: q.question_id, stem: q.stem, options: jsonValue(q.options_json, []), subject: q.subject, topic: q.topic, explanation: q.explanation }, studentAnswer: q.answer_index === null ? null : q.answer_index, correctAnswer: q.correct_index, isCorrect: q.answer_index !== null && q.answer_index === q.correct_index, attempted: q.answer_index !== null }));
  return { ...publicResultRow(row), questions, rank: rankFor(db, user.id)?.rank || null, percentile: rankFor(db, user.id)?.percentile || null };
}
function hasAttempts(db, testId) { return Boolean(dbRow(db, 'SELECT 1 AS ok FROM attempts WHERE test_id = ? LIMIT 1', testId)); }

function parseUploadedFile(fileData, fileName) {
  const name = path.basename(String(fileName || 'upload.bin')).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
  const ext = path.extname(name).toLowerCase();
  const allowed = new Set(['.pdf', '.png', '.jpg', '.jpeg', '.txt']);
  if (!allowed.has(ext)) throw new Error('FILE_TYPE');
  let raw = String(fileData || '').replace(/^data:[^;]+;base64,/, '');
  if (!raw || !/^(?:[a-z0-9+/]{4})*(?:[a-z0-9+/]{2}==|[a-z0-9+/]{3}=)?$/i.test(raw)) throw new Error('FILE_DATA');
  const buffer = Buffer.from(raw, 'base64');
  if (!buffer.length || buffer.length > MAX_FILE) throw new Error('FILE_SIZE');
  const magic = ext === '.pdf' ? buffer.subarray(0, 5).toString() === '%PDF-'
    : ext === '.png' ? buffer.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))
    : ['.jpg', '.jpeg'].includes(ext) ? buffer.subarray(0, 3).equals(Buffer.from([255,216,255]))
    : !buffer.includes(0) && Buffer.from(buffer.toString('utf8'), 'utf8').equals(buffer);
  if (!magic) throw new Error('FILE_MAGIC');
  return { name, buffer };
}
function writeUpload(file) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  const stored = `${crypto.randomUUID()}${path.extname(file.name).toLowerCase()}`;
  fs.writeFileSync(path.join(UPLOAD_DIR, stored), file.buffer, { mode: 0o600 });
  return stored;
}
function removeUpload(stored) { if (stored) try { fs.unlinkSync(path.join(UPLOAD_DIR, path.basename(stored))); } catch {} }

async function callAI(prompt, structured = false) {
  if (!AI_CONFIGURED) return null;
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(process.env.AI_API_URL, { method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.AI_API_KEY}` }, body: JSON.stringify({ model: process.env.AI_MODEL || 'gpt-4o-mini', messages: [{ role: 'system', content: structured ? 'Return only valid JSON matching the requested schema. Do not add markdown.' : 'Answer concisely and honestly in Hindi when possible.' }, { role: 'user', content: prompt }], temperature: 0.2 }) });
    if (!response.ok) throw new Error(`provider ${response.status}`);
    const data = await response.json(); const text = data.choices?.[0]?.message?.content || data.output_text;
    if (!text) throw new Error('empty provider response');
    if (!structured) return String(text).slice(0, 8000);
    const parsed = JSON.parse(String(text).replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, ''));
    return parsed;
  } finally { clearTimeout(timer); }
}
function validateGenerated(payload, exam, materialId) {
  if (!payload || !Array.isArray(payload.questions) || payload.questions.length < 1 || payload.questions.length > 30) throw new Error('AI_SHAPE');
  return payload.questions.map((q) => {
    if (!q || typeof q.stem !== 'string' || !Array.isArray(q.options) || q.options.length < 2 || q.options.length > 6 || !Number.isInteger(q.correctIndex) || q.correctIndex < 0 || q.correctIndex >= q.options.length || typeof q.explanation !== 'string') throw new Error('AI_SHAPE');
    return { exam, subject: clean(q.subject, 100), topic: clean(q.topic, 100), difficulty: difficultyValue(q.difficulty) || 'Medium', stem: clean(q.stem, 2000), options: q.options.map((x) => clean(x, 400)), correctIndex: q.correctIndex, explanation: clean(q.explanation, 2000), materialId };
  });
}
async function localAIAnswer(db, user, prompt, questionId) {
  const performance = metrics(db, user.id);
  if (questionId) {
    const q = dbRow(db, 'SELECT * FROM questions WHERE id = ? AND published = 1', questionId);
    if (!q) throw new Error('QUESTION_NOT_FOUND');
    return { answer: `यह ${q.subject} / ${q.topic} का original practice question है। पहले विकल्पों को eliminate करके हल करें; उत्तर और explanation देखने के लिए practice endpoint इस्तेमाल करें।`, provider: 'local study helper' };
  }
  const focus = performance.weakTopics.slice(0, 3).join(', ') || 'अभी कोई measured weak topic नहीं';
  return { answer: `आपके submitted attempts के आधार पर focus topics: ${focus}। अभी कोई external AI provider configured नहीं है, इसलिए यह bank और वास्तविक performance पर आधारित local सुझाव है।`, provider: 'local study helper' };
}

function validateQuestionInput(body) {
  const exam = examValue(body.exam); const difficulty = difficultyValue(body.difficulty);
  const options = Array.isArray(body.options) ? body.options.map((x) => clean(x, 400)) : [];
  const correctIndex = asInt(body.correctIndex);
  if (!exam || !clean(body.subject, 100) || !clean(body.topic, 100) || !difficulty || !clean(body.stem, 2000) || options.length < 2 || options.length > 6 || options.some((x) => !x) || !Number.isInteger(correctIndex) || correctIndex < 0 || correctIndex >= options.length || !clean(body.explanation, 2000)) throw new Error('QUESTION_INVALID');
  return { exam, subject: clean(body.subject, 100), topic: clean(body.topic, 100), difficulty, year: body.year === null || body.year === undefined || body.year === '' ? null : asInt(body.year), type: clean(body.type, 30) || 'MCQ', stem: clean(body.stem, 2000), options, correctIndex, explanation: clean(body.explanation, 2000), source: clean(body.source, 300) || 'Original practice question — not a previous-year paper', published: body.published === undefined ? true : bool(body.published) };
}
function addQuestion(db, input, createdBy) {
  const questionId = id('q');
  dbRun(db, `INSERT INTO questions (id,exam,subject,topic,difficulty,year,type,stem,options_json,correct_index,explanation,source,published,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, questionId, input.exam, input.subject, input.topic, input.difficulty, input.year, input.type, input.stem, JSON.stringify(input.options), input.correctIndex, input.explanation, input.source, input.published ? 1 : 0, createdBy, now());
  return dbRow(db, 'SELECT * FROM questions WHERE id = ?', questionId);
}

async function routeApi(db, req, res, url) {
  const method = req.method; const pathname = url.pathname;
  if (!rateLimit(req, res, pathname.startsWith('/api/auth') ? 'auth' : 'api', pathname.startsWith('/api/auth') ? 20 : 240)) return;
  if (!checkOrigin(req, res)) return;
  if (method === 'GET' && pathname === '/api/health') return sendJson(res, 200, { ok: true, database: 'sqlite', aiConfigured: AI_CONFIGURED });
  if (method === 'GET' && pathname === '/api/me') return sendJson(res, 200, { user: publicUser(currentUser(db, req)) });

  if (method === 'POST' && pathname === '/api/auth/register') {
    let body; try { body = await readBody(req); } catch (error) { return fail(res, error.code === 'BODY_TOO_LARGE' ? 413 : 400, error.code === 'BODY_TOO_LARGE' ? 'Request 5MB से छोटा रखें।' : 'Request body valid JSON नहीं है।'); }
    const name = clean(body.name, 80); const email = cleanEmail(body.email); const password = String(body.password || ''); const exam = examValue(body.exam);
    if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8 || password.length > 256 || !exam) return fail(res, 400, 'नाम, valid email, exam और कम से कम 8 characters का password दें।');
    if (dbRow(db, 'SELECT 1 AS ok FROM users WHERE email = ?', email)) return fail(res, 409, 'इस email से account पहले से मौजूद है।');
    const credentials = hashPassword(password); const userId = id('student'); const timestamp = now();
    try {
      transaction(db, () => { dbRun(db, 'INSERT INTO users (id,name,email,password_hash,password_salt,role,exam,created_at) VALUES (?,?,?,?,?,?,?,?)', userId, name, email, credentials.hash, credentials.salt, 'student', exam, timestamp); dbRun(db, 'INSERT INTO students (user_id,target_exam,joined_at) VALUES (?,?,?)', userId, exam === 'SSC' ? 'SSC' : 'UPSC Civil Services', timestamp); dbRun(db, 'INSERT INTO student_progress (user_id,exam,last_active_at) VALUES (?,?,?)', userId, exam, timestamp); });
    } catch (error) { if (errorMessage(error).includes('UNIQUE')) return fail(res, 409, 'इस email से account पहले से मौजूद है।'); throw error; }
    const token = sessionToken(db, userId); return sendJson(res, 201, { user: publicUser(dbRow(db, 'SELECT * FROM users WHERE id = ?', userId)) }, { 'Set-Cookie': cookieHeader(token) });
  }
  if (method === 'POST' && pathname === '/api/auth/login') {
    let body; try { body = await readBody(req); } catch (error) { return fail(res, error.code === 'BODY_TOO_LARGE' ? 413 : 400, 'Request body valid JSON नहीं है।'); }
    const user = dbRow(db, 'SELECT * FROM users WHERE email = ? AND active = 1', cleanEmail(body.email));
    const role = body.role === undefined || body.role === '' ? null : clean(body.role, 20);
    if (!user || String(body.password || '').length > 256 || (role && user.role !== role) || !verifyPassword(body.password, user)) return fail(res, 401, 'Email या password सही नहीं है।');
    const token = sessionToken(db, user.id); return sendJson(res, 200, { user: publicUser(user) }, { 'Set-Cookie': cookieHeader(token) });
  }
  if (method === 'POST' && pathname === '/api/auth/logout') { removeSession(db, req); return sendJson(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) }); }

  if (method === 'GET' && pathname === '/api/catalog') return sendJson(res, 200, { exams: dbRows(db, 'SELECT id,code,name,description,active FROM exams WHERE active = 1'), subjects: dbRows(db, 'SELECT id,exam_code AS exam,name,active FROM subjects WHERE active = 1'), topics: dbRows(db, 'SELECT id,exam_code AS exam,subject_name AS subject,name,active FROM topics WHERE active = 1'), courses: dbRows(db, 'SELECT id,title,exam_code AS exam,level,lessons,premium,description FROM courses') });

  const user = requireUser(db, req, res); if (!user) return;
  if (method === 'GET' && pathname === '/api/dashboard') return sendJson(res, 200, dashboard(db, user));
  if (method === 'GET' && pathname === '/api/tests') {
    const exam = url.searchParams.get('exam'); const category = url.searchParams.get('category');
    const tests = dbRows(db, `SELECT t.*, COUNT(tq.question_id) AS question_count FROM tests t LEFT JOIN test_questions tq ON tq.test_id = t.id WHERE ((t.published = 1 AND t.owner_user_id IS NULL) OR t.owner_user_id = ?) AND (? IS NULL OR t.exam = ?) AND (? IS NULL OR t.category = ?) GROUP BY t.id ORDER BY t.created_at DESC`, user.id, exam, exam, category, category).map((t) => ({ id: t.id, title: t.title, exam: t.exam, category: t.category, description: t.description, durationMinutes: t.duration_minutes, negativeMarking: t.negative_marking, positiveMarking: t.positive_marking, questionCount: t.question_count, published: Boolean(t.published) }));
    return sendJson(res, 200, { tests });
  }
  const testMatch = pathname.match(/^\/api\/tests\/([^/]+)$/);
  if (method === 'GET' && testMatch) { const test = testRow(db, decodeURIComponent(testMatch[1])); if (!canSeeTest(user, test)) return fail(res, 404, 'Test नहीं मिला।'); return sendJson(res, 200, { test: testView(db, test) }); }
  const startMatch = pathname.match(/^\/api\/tests\/([^/]+)\/start$/);
  if (method === 'POST' && startMatch) {
    if (user.role !== 'student') return fail(res, 403, 'यह test flow student account के लिए है।');
    const test = testRow(db, decodeURIComponent(startMatch[1])); if (!canSeeTest(user, test)) return fail(res, 404, 'Test नहीं मिला।');
    if (test.premium && !userEntitled(db, user, 'premium')) return fail(res, 403, 'यह premium test आपके account में उपलब्ध नहीं है।');
    const existing = dbRow(db, "SELECT * FROM attempts WHERE user_id = ? AND test_id = ? AND status = 'in-progress'", user.id, test.id);
    if (existing) return sendJson(res, 200, attemptData(db, existing));
    const questions = testQuestions(db, test.id); if (!questions.length) return fail(res, 400, 'इस test में अभी questions नहीं हैं।');
    const timestamp = now(); const deadline = new Date(Date.now() + test.duration_minutes * 60_000).toISOString(); const attemptId = id('attempt');
    try {
      transaction(db, () => { dbRun(db, `INSERT INTO attempts (id,user_id,test_id,status,started_at,deadline_at,total_questions) VALUES (?,?,?,?,?,?,?)`, attemptId, user.id, test.id, 'in-progress', timestamp, deadline, questions.length); questions.forEach((q) => dbRun(db, 'INSERT INTO attempt_questions (attempt_id,question_id,position,stem,options_json,subject,topic,difficulty,explanation,correct_index) VALUES (?,?,?,?,?,?,?,?,?,?)', attemptId, q.id, q.position, q.stem, q.options_json, q.subject, q.topic, q.difficulty, q.explanation, q.correct_index)); });
    } catch (error) { if (errorMessage(error).includes('UNIQUE')) { const retry = dbRow(db, "SELECT * FROM attempts WHERE user_id = ? AND test_id = ? AND status = 'in-progress'", user.id, test.id); if (retry) return sendJson(res, 200, attemptData(db, retry)); } throw error; }
    return sendJson(res, 201, attemptData(db, dbRow(db, 'SELECT * FROM attempts WHERE id = ?', attemptId)));
  }
  const attemptMatch = pathname.match(/^\/api\/attempts\/([^/]+)$/); const answerMatch = pathname.match(/^\/api\/attempts\/([^/]+)\/answers$/); const submitMatch = pathname.match(/^\/api\/attempts\/([^/]+)\/submit$/);
  if ((method === 'GET' || method === 'PUT' || method === 'POST') && (attemptMatch || answerMatch || submitMatch)) {
    const attemptId = decodeURIComponent((attemptMatch || answerMatch || submitMatch)[1]); const attempt = dbRow(db, 'SELECT * FROM attempts WHERE id = ? AND user_id = ?', attemptId, user.id); if (!attempt) return fail(res, 404, 'Attempt नहीं मिला।');
    if (method === 'GET' && attemptMatch) return sendJson(res, 200, attemptData(db, attempt));
    if (method === 'PUT' && answerMatch) {
      if (attempt.status !== 'in-progress') return fail(res, 409, 'यह attempt पहले submit हो चुका है।');
      if (new Date(attempt.deadline_at).getTime() <= Date.now()) return fail(res, 409, 'इस attempt का समय समाप्त हो गया है।');
      let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); }
      try { const review = assertAnswerMap(db, attempt, body.answers, body.review); const reviewSet = review ? new Set(review) : null; transaction(db, () => { for (const [questionId, raw] of Object.entries(body.answers || {})) { const answer = raw === null || raw === '' ? null : asInt(raw); dbRun(db, `INSERT INTO answers (attempt_id,question_id,answer_index,marked_review,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(attempt_id,question_id) DO UPDATE SET answer_index=excluded.answer_index, marked_review=excluded.marked_review, updated_at=excluded.updated_at`, attempt.id, questionId, answer, reviewSet ? (reviewSet.has(questionId) ? 1 : 0) : 0, now()); } if (reviewSet) dbRun(db, 'UPDATE answers SET marked_review = 0 WHERE attempt_id = ?', attempt.id); if (reviewSet) for (const questionId of reviewSet) dbRun(db, 'UPDATE answers SET marked_review = 1 WHERE attempt_id = ? AND question_id = ?', attempt.id, questionId); }); return sendJson(res, 200, { savedAt: now(), deadlineAt: attempt.deadline_at, serverNow: now() }); } catch (error) { const messages = { ANSWERS_OBJECT: 'Answers object जरूरी है।', QUESTION_NOT_IN_ATTEMPT: 'यह question इस attempt का हिस्सा नहीं है।', INVALID_ANSWER_INDEX: 'Answer index valid नहीं है।', INVALID_REVIEW: 'Review list valid नहीं है।' }; return fail(res, 400, messages[error.message] || 'Answers save नहीं हो सके।'); }
    }
    if (method === 'POST' && submitMatch) {
      if (attempt.status === 'submitted') { const existingResult = dbRow(db, 'SELECT r.*, t.title AS test_title FROM results r JOIN tests t ON t.id = r.test_id WHERE r.attempt_id = ?', attempt.id); return sendJson(res, 200, { result: publicResultRow(existingResult) }); }
      const test = testRow(db, attempt.test_id); const answerRows = dbRows(db, 'SELECT aq.*, a.answer_index FROM attempt_questions aq LEFT JOIN answers a ON a.attempt_id = aq.attempt_id AND a.question_id = aq.question_id WHERE aq.attempt_id = ?', attempt.id);
      const attempted = answerRows.filter((a) => a.answer_index !== null).length; const correct = answerRows.filter((a) => a.answer_index !== null && a.answer_index === a.correct_index).length; const incorrect = attempted - correct; const unattempted = answerRows.length - attempted; const score = Math.round((correct * test.positive_marking - incorrect * test.negative_marking) * 100) / 100; const maxScore = Math.round(answerRows.length * test.positive_marking * 100) / 100; const elapsed = Math.max(0, Math.min(Math.floor((Date.now() - new Date(attempt.started_at).getTime()) / 1000), Math.floor(test.duration_minutes * 60))); const accuracy = attempted ? Math.round(correct / attempted * 100) : 0; const submittedAt = now();
      let result;
      transaction(db, () => { const fresh = dbRow(db, 'SELECT status FROM attempts WHERE id = ?', attempt.id); if (fresh.status === 'submitted') return; dbRun(db, `UPDATE attempts SET status='submitted',submitted_at=?,time_taken_seconds=?,attempted=?,correct=?,incorrect=?,unattempted=?,score=?,accuracy=? WHERE id=? AND status='in-progress'`, submittedAt, elapsed, attempted, correct, incorrect, unattempted, score, accuracy, attempt.id); const resultId = id('result'); dbRun(db, `INSERT INTO results (id,attempt_id,user_id,test_id,total_questions,attempted,correct,incorrect,unattempted,score,max_score,accuracy,time_taken_seconds,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, resultId, attempt.id, user.id, test.id, answerRows.length, attempted, correct, incorrect, unattempted, score, maxScore, accuracy, elapsed, submittedAt); dbRun(db, 'UPDATE student_progress SET study_minutes = study_minutes + ?, last_active_at = ? WHERE user_id = ?', Math.ceil(elapsed / 60), submittedAt, user.id); result = dbRow(db, 'SELECT r.*, t.title AS test_title FROM results r JOIN tests t ON t.id = r.test_id WHERE r.id = ?', resultId); });
      if (!result) result = dbRow(db, 'SELECT r.*, t.title AS test_title FROM results r JOIN tests t ON t.id = r.test_id WHERE r.attempt_id = ?', attempt.id);
      return sendJson(res, 200, { result: publicResultRow(result) });
    }
  }

  if (method === 'GET' && pathname === '/api/results') return sendJson(res, 200, { results: submittedRows(db, user.id).map(publicResultRow) });
  const resultMatch = pathname.match(/^\/api\/results\/([^/]+)$/);
  if (method === 'GET' && resultMatch) { const value = decodeURIComponent(resultMatch[1]); const row = dbRow(db, `SELECT r.*, t.title AS test_title FROM results r JOIN tests t ON t.id = r.test_id WHERE (r.id = ? OR r.attempt_id = ?) AND r.user_id = ?`, value, value, user.id); if (!row) return fail(res, 404, 'Result नहीं मिला।'); return sendJson(res, 200, { result: detailedResult(db, row, user), performance: metrics(db, user.id), plan: planFor(db, user) }); }

  if (method === 'GET' && pathname === '/api/materials') { const exam = url.searchParams.get('exam'); const term = clean(url.searchParams.get('q'), 100).toLowerCase(); const materials = dbRows(db, 'SELECT * FROM materials WHERE published = 1 AND (? IS NULL OR exam = ?) ORDER BY created_at DESC', exam, exam).filter((m) => (!m.premium || userEntitled(db, user, 'premium')) && (!term || [m.title, m.description, m.subject, m.topic, m.chapter].join(' ').toLowerCase().includes(term))).map(materialView); return sendJson(res, 200, { materials }); }
  const materialMatch = pathname.match(/^\/api\/materials\/([^/]+)$/); const materialFileMatch = pathname.match(/^\/api\/materials\/([^/]+)\/file$/);
  if (method === 'GET' && (materialMatch || materialFileMatch)) { const material = dbRow(db, 'SELECT * FROM materials WHERE id = ? AND published = 1', decodeURIComponent((materialMatch || materialFileMatch)[1])); if (!material) return fail(res, 404, 'Material नहीं मिला।'); if (material.premium && !userEntitled(db, user, 'premium')) return fail(res, 403, 'यह premium material आपके account में उपलब्ध नहीं है।'); if (materialFileMatch) { if (!material.file_path) return fail(res, 404, 'इस material की file उपलब्ध नहीं है।'); const full = path.join(UPLOAD_DIR, path.basename(material.file_path)); if (!fs.existsSync(full)) return fail(res, 404, 'File नहीं मिली।'); res.writeHead(200, { 'Content-Type': material.type.toLowerCase().includes('pdf') ? 'application/pdf' : 'application/octet-stream', 'Content-Disposition': `attachment; filename="${material.file_name || 'material.bin'}"`, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, no-store' }); return fs.createReadStream(full).pipe(res); } return sendJson(res, 200, { material: materialView(material), body: material.content, source: material.source_url }); }

  if (method === 'GET' && pathname === '/api/questions') {
    let rows = dbRows(db, 'SELECT * FROM questions WHERE published = 1'); const params = url.searchParams;
    for (const key of ['exam', 'subject', 'topic', 'difficulty']) if (params.get(key)) rows = rows.filter((q) => q[key] === params.get(key));
    if (params.get('year')) rows = rows.filter((q) => String(q.year) === params.get('year'));
    if (params.get('q')) { const term = clean(params.get('q'), 100).toLowerCase(); rows = rows.filter((q) => `${q.stem} ${q.subject} ${q.topic}`.toLowerCase().includes(term)); }
    if (params.get('status')) { const statuses = new Map(dbRows(db, 'SELECT question_id,is_correct FROM practice_answers WHERE user_id = ?', user.id).map((x) => [x.question_id, x.is_correct ? 'correct' : 'incorrect'])); rows = rows.filter((q) => (statuses.get(q.id) || 'unattempted') === params.get('status')); }
    return sendJson(res, 200, { questions: rows.slice(0, 100).map(questionView) });
  }
  const practiceMatch = pathname.match(/^\/api\/questions\/([^/]+)\/practice$/);
  if (method === 'POST' && practiceMatch) { const q = dbRow(db, 'SELECT * FROM questions WHERE id = ? AND published = 1', decodeURIComponent(practiceMatch[1])); if (!q) return fail(res, 404, 'Question नहीं मिला।'); let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const answer = asInt(body.answer); if (!Number.isInteger(answer) || answer < 0 || answer >= jsonValue(q.options_json, []).length) return fail(res, 400, 'Answer index valid नहीं है।'); const isCorrect = answer === q.correct_index; dbRun(db, `INSERT INTO practice_answers (user_id,question_id,answer_index,is_correct,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(user_id,question_id) DO UPDATE SET answer_index=excluded.answer_index,is_correct=excluded.is_correct,updated_at=excluded.updated_at`, user.id, q.id, answer, isCorrect ? 1 : 0, now()); return sendJson(res, 200, { correctAnswer: q.correct_index, explanation: q.explanation, isCorrect }); }

  if (method === 'POST' && pathname === '/api/tests/custom') {
    if (user.role !== 'student') return fail(res, 403, 'यह test flow student account के लिए है।'); let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); }
    const exam = examValue(body.exam) || user.exam; const count = Math.max(1, Math.min(50, asInt(body.count, 10))); const durationMinutes = Math.max(1, Math.min(240, asInt(body.durationMinutes, count * 2))); const positive = Number(body.positiveMarking ?? 1); const negative = Number(body.negativeMarking ?? (exam === 'UPSC' ? 0.33 : 0.25)); if (!Number.isFinite(positive) || positive <= 0 || !Number.isFinite(negative) || negative < 0) return fail(res, 400, 'Marking values valid नहीं हैं।');
    const filters = ['exam = ?']; const params = [exam]; for (const [key, value] of [['subject', body.subject], ['topic', body.topic], ['difficulty', body.difficulty]]) if (value) { filters.push(`${key} = ?`); params.push(clean(value, 100)); } const questions = dbRows(db, `SELECT id FROM questions WHERE published = 1 AND ${filters.join(' AND ')} ORDER BY RANDOM() LIMIT ?`, ...params, count); if (!questions.length) return fail(res, 400, 'इन filters में questions नहीं मिले।'); const testId = id('test'); const timestamp = now(); transaction(db, () => { dbRun(db, 'INSERT INTO tests (id,title,exam,category,description,duration_minutes,positive_marking,negative_marking,published,premium,owner_user_id,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,0,0,?,?,?,?)', testId, clean(body.title, 160) || 'Personal Practice Test', exam, 'Custom Practice', 'आपके चुने हुए filters से बना personal test।', durationMinutes, positive, negative, user.id, user.id, timestamp, timestamp); questions.forEach((q, index) => dbRun(db, 'INSERT INTO test_questions (test_id,question_id,position) VALUES (?,?,?)', testId, q.id, index)); }); const test = testRow(db, testId); return sendJson(res, 201, { test: testView(db, test) });
  }
  if (method === 'POST' && pathname === '/api/ai/generate-quiz') {
    if (user.role !== 'student') return fail(res, 403, 'AI quiz student account के लिए है।'); let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const exam = examValue(body.exam) || user.exam; const count = Math.max(1, Math.min(20, asInt(body.count, 10))); const performance = metrics(db, user.id); const placeholders = performance.weakTopics.length ? performance.weakTopics : ['']; let rows = dbRows(db, `SELECT id FROM questions WHERE published = 1 AND exam = ? AND topic IN (${placeholders.map(() => '?').join(',')}) ORDER BY RANDOM() LIMIT ?`, exam, ...placeholders, count); if (rows.length < count) rows = [...rows, ...dbRows(db, 'SELECT id FROM questions WHERE published = 1 AND exam = ? AND id NOT IN (' + (rows.length ? rows.map(() => '?').join(',') : "''") + ') ORDER BY RANDOM() LIMIT ?', exam, ...rows.map((x) => x.id), count - rows.length)]; if (!rows.length) return fail(res, 400, 'इस exam के लिए practice bank खाली है।'); const testId = id('test'); const timestamp = now(); transaction(db, () => { dbRun(db, 'INSERT INTO tests (id,title,exam,category,description,duration_minutes,positive_marking,negative_marking,published,premium,owner_user_id,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,0,0,?,?,?,?)', testId, `Personalized practice · ${exam}`, exam, 'Bank Practice', 'आपकी वास्तविक mistakes के topics से चुना गया original practice set।', Math.max(1, rows.length * 2), 1, exam === 'UPSC' ? 0.33 : 0.25, user.id, user.id, timestamp, timestamp); rows.forEach((q, index) => dbRun(db, 'INSERT INTO test_questions (test_id,question_id,position) VALUES (?,?,?)', testId, q.id, index)); }); return sendJson(res, 201, { test: testView(db, testRow(db, testId)), generatedBy: 'local question bank', reviewNotice: 'यह AI-generated content नहीं है; यह original bank-based practice है।' });
  }
  if (method === 'POST' && pathname === '/api/ai/ask') { let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const prompt = clean(body.prompt, 1000); if (!prompt) return fail(res, 400, 'अपना सवाल लिखें।'); if (AI_CONFIGURED) { try { const answer = await callAI(`Student exam: ${user.exam}. Do not invent current facts. Prompt: ${prompt}`); if (answer) return sendJson(res, 200, { answer, provider: 'configured AI provider' }); } catch (error) { console.error('AI provider error:', error.message); } } try { return sendJson(res, 200, await localAIAnswer(db, user, prompt, body.questionId)); } catch (error) { if (error.message === 'QUESTION_NOT_FOUND') return fail(res, 404, 'Question नहीं मिला।'); throw error; } }

  if (method === 'GET' && pathname === '/api/daily-quiz') { const date = new Date().toISOString().slice(0, 10); const title = `Daily Quiz · ${date}`; let dailyTest = dbRow(db, 'SELECT * FROM tests WHERE owner_user_id = ? AND category = ? AND title = ?', user.id, 'Daily Quiz', title); if (!dailyTest) { const seed = [...Buffer.from(`${date}:${user.id}`)].reduce((a, b) => a + b, 0); const rows = dbRows(db, 'SELECT id FROM questions WHERE published = 1 AND exam = ? ORDER BY id', user.exam); let selected = rows.filter((_, index) => index % Math.max(1, Math.floor((seed % 5) + 1)) === 0).slice(0, 10); if (!selected.length) selected = rows.slice(0, 10); if (!selected.length) return fail(res, 400, 'Daily quiz के लिए practice questions नहीं हैं।'); const testId = id('test'); const timestamp = now(); transaction(db, () => { dbRun(db, 'INSERT INTO tests (id,title,exam,category,description,duration_minutes,positive_marking,negative_marking,published,premium,owner_user_id,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,0,0,?,?,?,?)', testId, title, user.exam, 'Daily Quiz', 'आज का original bank-based practice quiz।', Math.max(1, selected.length * 2), 1, user.exam === 'UPSC' ? 0.33 : 0.25, user.id, user.id, timestamp, timestamp); selected.forEach((q, index) => dbRun(db, 'INSERT INTO test_questions (test_id,question_id,position) VALUES (?,?,?)', testId, q.id, index)); }); dailyTest = testRow(db, testId); } return sendJson(res, 200, { test: testView(db, dailyTest) }); }
  if (method === 'GET' && pathname === '/api/current-affairs') { const category = url.searchParams.get('category'); const rows = dbRows(db, 'SELECT * FROM current_affairs WHERE (? IS NULL OR category = ?) ORDER BY published_at DESC', category, category).map((x) => ({ id: x.id, title: x.title, category: x.category, publishedAt: x.published_at, shortExplanation: x.short_explanation, detailedExplanation: x.detailed_explanation, importantFacts: jsonValue(x.important_facts_json, []), sourceLabel: x.source_label, sourceUrl: x.source_url })); return sendJson(res, 200, { items: rows, categories: unique(dbRows(db, 'SELECT category FROM current_affairs ORDER BY category').map((x) => x.category)) }); }
  if (method === 'GET' && pathname === '/api/leaderboard') { const period = ['daily','weekly','monthly','overall'].includes(url.searchParams.get('period')) ? url.searchParams.get('period') : 'overall'; const days = period === 'daily' ? 1 : period === 'weekly' ? 7 : period === 'monthly' ? 30 : null; const condition = days ? "AND r.created_at >= datetime('now', ?)" : ''; const args = days ? [`-${days} days`] : []; const rows = dbRows(db, `SELECT u.id,u.name,COALESCE(SUM(r.score),0) AS score,COUNT(r.id) AS tests_completed,CASE WHEN COALESCE(SUM(r.attempted),0)=0 THEN 0 ELSE ROUND(SUM(r.correct)*100.0/SUM(r.attempted)) END AS accuracy FROM users u JOIN results r ON r.user_id=u.id ${condition} WHERE u.role='student' AND u.active=1 GROUP BY u.id ORDER BY score DESC, accuracy DESC`, ...args).map((r, index) => ({ rank: index + 1, user: { id: r.id, name: r.name }, score: r.score, testsCompleted: r.tests_completed, accuracy: r.accuracy, streak: streak(db, r.id) })); return sendJson(res, 200, { leaders: rows, mine: rows.find((x) => x.user.id === user.id) || null }); }
  if (method === 'GET' && pathname === '/api/notifications') return sendJson(res, 200, { notifications: dbRows(db, 'SELECT id,title,body,type,is_read AS read,created_at AS createdAt FROM notifications WHERE user_id = ? OR user_id IS NULL ORDER BY created_at DESC', user.id) });
  if (method === 'POST' && pathname === '/api/notifications/read') { let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const ids = Array.isArray(body.ids) ? body.ids.map((x) => clean(x, 120)).slice(0, 100) : []; if (ids.length) for (const notificationId of ids) dbRun(db, 'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?', notificationId, user.id); else dbRun(db, 'UPDATE notifications SET is_read = 1 WHERE user_id = ?', user.id); return sendJson(res, 200, { ok: true }); }
  if (method === 'GET' && pathname === '/api/library') { const marks = dbRows(db, 'SELECT * FROM bookmarks WHERE user_id = ? ORDER BY created_at DESC', user.id).map((mark) => ({ id: mark.id, entityType: mark.entity_type, entityId: mark.entity_id, item: mark.entity_type === 'material' ? materialView(dbRow(db, 'SELECT * FROM materials WHERE id = ?', mark.entity_id) || {}) : questionView(dbRow(db, 'SELECT * FROM questions WHERE id = ?', mark.entity_id) || {}) })); return sendJson(res, 200, { bookmarks: marks, notes: dbRows(db, 'SELECT id,title,content,entity_type AS entityType,entity_id AS entityId,created_at AS createdAt,updated_at AS updatedAt FROM notes WHERE user_id = ? ORDER BY updated_at DESC', user.id) }); }
  if (method === 'POST' && pathname === '/api/bookmarks') { let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const entityType = clean(body.entityType, 40); const entityId = clean(body.entityId, 120); if (!['material','question'].includes(entityType) || !entityId) return fail(res, 400, 'Bookmark entity valid नहीं है।'); const exists = dbRow(db, 'SELECT * FROM bookmarks WHERE user_id = ? AND entity_type = ? AND entity_id = ?', user.id, entityType, entityId); if (exists) dbRun(db, 'DELETE FROM bookmarks WHERE id = ?', exists.id); else { const valid = entityType === 'material' ? dbRow(db, 'SELECT 1 FROM materials WHERE id = ? AND published = 1', entityId) : dbRow(db, 'SELECT 1 FROM questions WHERE id = ? AND published = 1', entityId); if (!valid) return fail(res, 404, 'Bookmark item नहीं मिला।'); dbRun(db, 'INSERT INTO bookmarks (id,user_id,entity_type,entity_id,created_at) VALUES (?,?,?,?,?)', id('bookmark'), user.id, entityType, entityId, now()); } return sendJson(res, 200, { bookmarked: !exists }); }
  if (method === 'POST' && pathname === '/api/notes') { let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const content = clean(body.content, 5000); if (!content) return fail(res, 400, 'Note खाली नहीं हो सकती।'); const noteId = id('note'); const timestamp = now(); dbRun(db, 'INSERT INTO notes (id,user_id,title,content,entity_type,entity_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)', noteId, user.id, clean(body.title, 160), content, clean(body.entityType, 40) || null, clean(body.entityId, 120) || null, timestamp, timestamp); return sendJson(res, 201, { note: dbRow(db, 'SELECT id,title,content,entity_type AS entityType,entity_id AS entityId,created_at AS createdAt,updated_at AS updatedAt FROM notes WHERE id = ?', noteId) }); }
  const noteMatch = pathname.match(/^\/api\/notes\/([^/]+)$/); if (method === 'DELETE' && noteMatch) { const result = dbRun(db, 'DELETE FROM notes WHERE id = ? AND user_id = ?', decodeURIComponent(noteMatch[1]), user.id); if (!result.changes) return fail(res, 404, 'Note नहीं मिली।'); return sendJson(res, 200, { ok: true }); }

  if (pathname.startsWith('/api/admin/')) return adminRoutes(db, req, res, url, user);
  return fail(res, 404, 'API route नहीं मिला।');
}

async function adminRoutes(db, req, res, url, user) {
  if (user.role !== 'admin') return fail(res, 403, 'Admin अनुमति आवश्यक है।');
  const method = req.method; const pathname = url.pathname;
  if (method === 'GET' && pathname === '/api/admin/stats') return sendJson(res, 200, { stats: { users: dbRow(db, "SELECT COUNT(*) AS n FROM users WHERE role='student'").n, materials: dbRow(db, 'SELECT COUNT(*) AS n FROM materials').n, tests: dbRow(db, 'SELECT COUNT(*) AS n FROM tests').n, questions: dbRow(db, 'SELECT COUNT(*) AS n FROM questions').n, pendingAI: dbRow(db, "SELECT COUNT(*) AS n FROM generated_drafts WHERE status='pending'").n } });
  if (method === 'GET' && pathname === '/api/admin/materials') return sendJson(res, 200, { materials: dbRows(db, 'SELECT * FROM materials ORDER BY created_at DESC').map(materialView) });
  if (method === 'GET' && pathname === '/api/admin/questions') return sendJson(res, 200, { questions: dbRows(db, 'SELECT * FROM questions ORDER BY created_at DESC').map(adminQuestionView) });
  if (method === 'GET' && pathname === '/api/admin/tests') return sendJson(res, 200, { tests: dbRows(db, 'SELECT * FROM tests ORDER BY created_at DESC').map((t) => testView(db, t, true)) });
  if (method === 'GET' && pathname === '/api/admin/users') return sendJson(res, 200, { users: dbRows(db, 'SELECT id,name,email,role,exam,active,created_at AS createdAt FROM users ORDER BY created_at DESC') });
  if (method === 'GET' && pathname === '/api/admin/ai-review') return sendJson(res, 200, { drafts: dbRows(db, `SELECT d.*,m.title AS material_title FROM generated_drafts d JOIN materials m ON m.id=d.material_id ORDER BY d.created_at DESC`).map((d) => ({ id: d.id, materialId: d.material_id, materialTitle: d.material_title, excerpt: d.excerpt, status: d.status, reviewNote: d.review_note, questions: jsonValue(d.payload_json, []), createdAt: d.created_at, reviewedAt: d.reviewed_at })) });
  if (method === 'POST' && pathname === '/api/admin/materials') {
    let body; try { body = await readBody(req); } catch (error) { return fail(res, error.code === 'BODY_TOO_LARGE' ? 413 : 400, error.code === 'BODY_TOO_LARGE' ? 'Request 5MB से छोटा रखें।' : 'Request body valid JSON नहीं है।'); }
    const title = clean(body.title, 160); const exam = examValue(body.exam); if (!title || !exam) return fail(res, 400, 'Title और exam जरूरी हैं।'); let file = null; try { if (body.fileData) file = parseUploadedFile(body.fileData, body.fileName); } catch (error) { const messages = { FILE_TYPE: 'File type स्वीकार नहीं है।', FILE_DATA: 'File data valid base64 नहीं है।', FILE_SIZE: 'File 5MB से छोटी होनी चाहिए।', FILE_MAGIC: 'File content अपने extension से match नहीं करता।' }; return fail(res, 400, messages[error.message] || 'File valid नहीं है।'); }
    let stored = null; try { if (file) stored = writeUpload(file); const timestamp = now(); const materialId = id('material'); dbRun(db, 'INSERT INTO materials (id,title,description,exam,subject,topic,chapter,type,content,premium,published,source_url,file_name,file_path,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', materialId, title, clean(body.description, 1000), exam, clean(body.subject, 100), clean(body.topic, 100), clean(body.chapter, 100), clean(body.type, 30) || 'Notes', clean(body.content, 200000), bool(body.premium) ? 1 : 0, bool(body.published) ? 1 : 0, safeUrl(body.sourceUrl), file?.name || null, stored, user.id, timestamp, timestamp); return sendJson(res, 201, { material: materialView(dbRow(db, 'SELECT * FROM materials WHERE id = ?', materialId)) }); } catch (error) { removeUpload(stored); throw error; }
  }
  const materialAdminMatch = pathname.match(/^\/api\/admin\/materials\/([^/]+)$/);
  if ((method === 'PATCH' || method === 'DELETE') && materialAdminMatch) {
    const materialId = decodeURIComponent(materialAdminMatch[1]); const material = dbRow(db, 'SELECT * FROM materials WHERE id = ?', materialId); if (!material) return fail(res, 404, 'Material नहीं मिला।');
    if (method === 'DELETE') { dbRun(db, 'DELETE FROM materials WHERE id = ?', materialId); removeUpload(material.file_path); return sendJson(res, 200, { ok: true }); }
    let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } let newFile = null; try { if (body.fileData) newFile = parseUploadedFile(body.fileData, body.fileName); } catch (error) { return fail(res, 400, 'File valid नहीं है।'); } let stored = null; if (newFile) stored = writeUpload(newFile); const values = { title: body.title === undefined ? material.title : clean(body.title, 160), description: body.description === undefined ? material.description : clean(body.description, 1000), content: body.content === undefined ? material.content : clean(body.content, 200000), published: body.published === undefined ? material.published : (bool(body.published) ? 1 : 0), premium: body.premium === undefined ? material.premium : (bool(body.premium) ? 1 : 0), source: body.sourceUrl === undefined ? material.source_url : safeUrl(body.sourceUrl), fileName: newFile ? newFile.name : material.file_name, filePath: newFile ? stored : material.file_path }; dbRun(db, 'UPDATE materials SET title=?,description=?,content=?,published=?,premium=?,source_url=?,file_name=?,file_path=?,updated_at=? WHERE id=?', values.title, values.description, values.content, values.published, values.premium, values.source, values.fileName, values.filePath, now(), materialId); if (newFile) removeUpload(material.file_path); return sendJson(res, 200, { material: materialView(dbRow(db, 'SELECT * FROM materials WHERE id = ?', materialId)) });
  }
  if (method === 'POST' && pathname === '/api/admin/questions') { let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } try { const input = validateQuestionInput(body); const question = addQuestion(db, input, user.id); return sendJson(res, 201, { question: adminQuestionView(question) }); } catch { return fail(res, 400, 'Question fields valid नहीं हैं।'); } }
  const adminQuestionMatch = pathname.match(/^\/api\/admin\/questions\/([^/]+)$/);
  if ((method === 'PATCH' || method === 'DELETE') && adminQuestionMatch) {
    const questionId = decodeURIComponent(adminQuestionMatch[1]); const question = dbRow(db, 'SELECT * FROM questions WHERE id = ?', questionId); if (!question) return fail(res, 404, 'Question नहीं मिला।');
    if (dbRow(db, 'SELECT 1 AS ok FROM attempt_questions WHERE question_id = ? LIMIT 1', questionId)) return fail(res, 409, 'इस question पर attempt मौजूद हैं; snapshot सुरक्षित रखने के लिए इसे edit नहीं किया जा सकता।');
    if (method === 'DELETE') { if (dbRow(db, 'SELECT 1 AS ok FROM test_questions WHERE question_id = ? LIMIT 1', questionId)) return fail(res, 409, 'यह question किसी test में उपयोग हो रहा है। पहले test से हटाएँ।'); dbRun(db, 'DELETE FROM questions WHERE id = ?', questionId); return sendJson(res, 200, { ok: true }); }
    let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); }
    try { const input = validateQuestionInput({ exam: body.exam ?? question.exam, subject: body.subject ?? question.subject, topic: body.topic ?? question.topic, difficulty: body.difficulty ?? question.difficulty, year: body.year === undefined ? question.year : body.year, type: body.type ?? question.type, stem: body.stem ?? question.stem, options: body.options ?? jsonValue(question.options_json, []), correctIndex: body.correctIndex ?? question.correct_index, explanation: body.explanation ?? question.explanation, source: body.source ?? question.source, published: body.published === undefined ? question.published : body.published }); dbRun(db, 'UPDATE questions SET exam=?,subject=?,topic=?,difficulty=?,year=?,type=?,stem=?,options_json=?,correct_index=?,explanation=?,source=?,published=? WHERE id=?', input.exam, input.subject, input.topic, input.difficulty, input.year, input.type, input.stem, JSON.stringify(input.options), input.correctIndex, input.explanation, input.source, input.published ? 1 : 0, questionId); return sendJson(res, 200, { question: adminQuestionView(dbRow(db, 'SELECT * FROM questions WHERE id = ?', questionId)) }); } catch { return fail(res, 400, 'Question fields valid नहीं हैं।'); }
  }
  if (method === 'POST' && pathname === '/api/admin/questions/import') { let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } if (!Array.isArray(body.questions) || body.questions.length < 1 || body.questions.length > 100) return fail(res, 400, 'Questions की संख्या 1 से 100 के बीच रखें।'); try { const created = transaction(db, () => body.questions.map((item) => addQuestion(db, validateQuestionInput(item), user.id))); return sendJson(res, 201, { questions: created.map(adminQuestionView) }); } catch { return fail(res, 400, 'Import में कोई question valid नहीं है।'); } }
  if (method === 'POST' && pathname === '/api/admin/tests') { let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const exam = examValue(body.exam); const questionIds = Array.isArray(body.questionIds) ? unique(body.questionIds.map((x) => clean(x, 120))) : []; const duration = asInt(body.durationMinutes); const positive = Number(body.positiveMarking ?? 1); const negative = Number(body.negativeMarking ?? 0); const questions = questionIds.map((q) => dbRow(db, 'SELECT * FROM questions WHERE id = ?', q)); if (!exam || !clean(body.title, 160) || !questionIds.length || questions.some((q) => !q || q.exam !== exam) || !Number.isInteger(duration) || duration < 1 || duration > 600 || positive <= 0 || negative < 0) return fail(res, 400, 'Test fields valid नहीं हैं।'); const testId = id('test'); const timestamp = now(); transaction(db, () => { dbRun(db, 'INSERT INTO tests (id,title,exam,category,description,duration_minutes,positive_marking,negative_marking,published,premium,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', testId, clean(body.title, 160), exam, clean(body.category, 80) || 'Practice Test', clean(body.description, 1000), duration, positive, negative, bool(body.published) ? 1 : 0, 0, user.id, timestamp, timestamp); questionIds.forEach((q, index) => dbRun(db, 'INSERT INTO test_questions (test_id,question_id,position) VALUES (?,?,?)', testId, q, index)); }); return sendJson(res, 201, { test: testView(db, testRow(db, testId), true) }); }
  const adminTestMatch = pathname.match(/^\/api\/admin\/tests\/([^/]+)$/);
  if ((method === 'PATCH' || method === 'DELETE') && adminTestMatch) { const testId = decodeURIComponent(adminTestMatch[1]); const test = testRow(db, testId); if (!test) return fail(res, 404, 'Test नहीं मिला।'); if (hasAttempts(db, testId)) return fail(res, 409, 'इस test पर attempt मौजूद हैं; content बदलना सुरक्षित नहीं है।'); if (method === 'DELETE') { dbRun(db, 'DELETE FROM tests WHERE id = ?', testId); return sendJson(res, 200, { ok: true }); } let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const questionIds = body.questionIds === undefined ? testQuestions(db, testId).map((q) => q.id) : unique(Array.isArray(body.questionIds) ? body.questionIds : []); const questions = questionIds.map((q) => dbRow(db, 'SELECT * FROM questions WHERE id = ?', q)); if (!questionIds.length || questions.some((q) => !q || q.exam !== test.exam)) return fail(res, 400, 'Question list valid नहीं है।'); transaction(db, () => { dbRun(db, 'UPDATE tests SET title=?,description=?,category=?,duration_minutes=?,positive_marking=?,negative_marking=?,published=?,updated_at=? WHERE id=?', body.title === undefined ? test.title : clean(body.title, 160), body.description === undefined ? test.description : clean(body.description, 1000), body.category === undefined ? test.category : clean(body.category, 80), body.durationMinutes === undefined ? test.duration_minutes : asInt(body.durationMinutes), body.positiveMarking === undefined ? test.positive_marking : Number(body.positiveMarking), body.negativeMarking === undefined ? test.negative_marking : Number(body.negativeMarking), body.published === undefined ? test.published : (bool(body.published) ? 1 : 0), now(), testId); dbRun(db, 'DELETE FROM test_questions WHERE test_id = ?', testId); questionIds.forEach((q, index) => dbRun(db, 'INSERT INTO test_questions (test_id,question_id,position) VALUES (?,?,?)', testId, q, index)); }); return sendJson(res, 200, { test: testView(db, testRow(db, testId), true) }); }
  if (method === 'POST' && pathname === '/api/admin/current-affairs') { let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const title = clean(body.title, 180); const short = clean(body.shortExplanation, 1000); const sourceUrl = safeUrl(body.sourceUrl); if (!title || !short || !sourceUrl) return fail(res, 400, 'Title, explanation और reputable source URL जरूरी हैं।'); const itemId = id('affair'); dbRun(db, 'INSERT INTO current_affairs (id,title,category,published_at,short_explanation,detailed_explanation,important_facts_json,source_label,source_url,created_by,is_demo) VALUES (?,?,?,?,?,?,?,?,?,?,0)', itemId, title, clean(body.category, 80) || 'General', now(), short, clean(body.detailedExplanation, 4000), JSON.stringify(arrayText(body.importantFacts, 10, 300)), clean(body.sourceLabel, 120), sourceUrl, user.id); return sendJson(res, 201, { item: dbRow(db, 'SELECT * FROM current_affairs WHERE id = ?', itemId) }); }
  const catalogMatch = pathname.match(/^\/api\/admin\/catalog\/(subjects|topics|courses)$/);
  if (method === 'POST' && catalogMatch) { let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } try { const kind = catalogMatch[1]; if (kind === 'subjects') { const exam = examValue(body.exam); const name = clean(body.name, 100); if (!exam || !name) throw new Error(); const subjectId = id('subject'); dbRun(db, 'INSERT INTO subjects (id,exam_code,name,active) VALUES (?,?,?,1)', subjectId, exam, name); return sendJson(res, 201, { subject: dbRow(db, 'SELECT id,exam_code AS exam,name,active FROM subjects WHERE id = ?', subjectId) }); } if (kind === 'topics') { const exam = examValue(body.exam); const subject = clean(body.subject, 100); const name = clean(body.name, 100); if (!exam || !subject || !name) throw new Error(); const topicId = id('topic'); dbRun(db, 'INSERT INTO topics (id,exam_code,subject_name,name,active) VALUES (?,?,?,?,1)', topicId, exam, subject, name); return sendJson(res, 201, { topic: dbRow(db, 'SELECT id,exam_code AS exam,subject_name AS subject,name,active FROM topics WHERE id = ?', topicId) }); } const courseId = id('course'); const exam = examValue(body.exam); if (!exam || !clean(body.title, 160)) throw new Error(); dbRun(db, 'INSERT INTO courses (id,title,exam_code,level,lessons,premium,description) VALUES (?,?,?,?,?,?,?)', courseId, clean(body.title, 160), exam, clean(body.level, 40) || 'Beginner', Math.max(0, asInt(body.lessons, 0)), bool(body.premium) ? 1 : 0, clean(body.description, 1000)); return sendJson(res, 201, { course: dbRow(db, 'SELECT id,title,exam_code AS exam,level,lessons,premium,description FROM courses WHERE id = ?', courseId) }); } catch { return fail(res, 400, 'Catalog fields valid नहीं हैं।'); } }
  const generateMatch = pathname === '/api/admin/ai/generate';
  if (method === 'POST' && generateMatch) { if (!AI_CONFIGURED) return fail(res, 503, 'AI provider configured नहीं है; draft नहीं बनाया गया।'); let body; try { body = await readBody(req); } catch { return fail(res, 400, 'Request body valid JSON नहीं है।'); } const material = dbRow(db, 'SELECT * FROM materials WHERE id = ?', clean(body.materialId, 120)); if (!material) return fail(res, 404, 'Material नहीं मिला।'); const excerpt = clean(body.excerpt || material.content, 12000); if (!excerpt) return fail(res, 400, 'Material text या admin excerpt जरूरी है।'); try { const payload = { questions: validateGenerated(await callAI(`Create original practice MCQs from this administrator-selected material. Exam: ${material.exam}. Return JSON only: {"questions":[{"stem":string,"options":string[],"correctIndex":integer,"explanation":string,"subject":string,"topic":string,"difficulty":"Easy|Medium|Hard"}]}. Do not copy a previous-year paper. Material text:\n${excerpt}`, true), material.exam, material.id) }; const draftId = id('draft'); dbRun(db, 'INSERT INTO generated_drafts (id,material_id,created_by,excerpt,payload_json,status,created_at) VALUES (?,?,?,?,?,?,?)', draftId, material.id, user.id, excerpt, JSON.stringify(payload.questions), 'pending', now()); return sendJson(res, 201, { draft: { id: draftId, materialId: material.id, status: 'pending', questions: payload.questions } }); } catch (error) { console.error('AI draft error:', error.message); return fail(res, 502, 'AI response structured और valid नहीं था; draft नहीं बनाया गया।'); } }
  const reviewMatch = pathname.match(/^\/api\/admin\/ai-review\/([^/]+)\/(approve|reject)$/);
  if (method === 'POST' && reviewMatch) { const draft = dbRow(db, 'SELECT * FROM generated_drafts WHERE id = ?', decodeURIComponent(reviewMatch[1])); if (!draft) return fail(res, 404, 'Draft नहीं मिला।'); if (draft.status !== 'pending') return fail(res, 409, 'Draft पहले review हो चुका है।'); const action = reviewMatch[2]; let body = {}; try { body = await readBody(req); } catch {} if (action === 'reject') { dbRun(db, 'UPDATE generated_drafts SET status="rejected",review_note=?,reviewed_at=? WHERE id=?', clean(body.note, 1000), now(), draft.id); return sendJson(res, 200, { id: draft.id, status: 'rejected' }); } const material = dbRow(db, 'SELECT * FROM materials WHERE id = ?', draft.material_id); const generated = jsonValue(draft.payload_json, []); try { const inputs = generated.map((q) => validateQuestionInput({ ...q, source: `AI draft from admin material ${material.title}; approved by admin`, published: true })); const created = transaction(db, () => inputs.map((input) => addQuestion(db, input, user.id))); dbRun(db, 'UPDATE generated_drafts SET status="approved",review_note=?,reviewed_at=? WHERE id=?', clean(body.note, 1000), now(), draft.id); return sendJson(res, 200, { id: draft.id, status: 'approved', questions: created.map(adminQuestionView) }); } catch { return fail(res, 400, 'Draft questions review के लिए valid नहीं हैं।'); } }
  return fail(res, 404, 'Admin endpoint नहीं मिला।');
}

function contentType(file) { return { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json' }[path.extname(file).toLowerCase()] || 'application/octet-stream'; }
function serveStatic(req, res, pathname) {
  let requested = pathname === '/' ? '/index.html' : pathname; if (requested.includes('..')) return fail(res, 400, 'Invalid path'); const full = path.resolve(PUBLIC_DIR, `.${requested}`); if (!full.startsWith(`${PUBLIC_DIR}${path.sep}`)) return fail(res, 400, 'Invalid path');
  fs.stat(full, (error, stat) => { if (!error && stat.isFile()) { res.writeHead(200, { 'Content-Type': contentType(full), 'X-Content-Type-Options': 'nosniff' }); fs.createReadStream(full).pipe(res); return; } if (pathname !== '/') { const index = path.join(PUBLIC_DIR, 'index.html'); if (fs.existsSync(index)) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' }); return fs.createReadStream(index).pipe(res); } } fail(res, 404, 'Not found'); });
}
function createServer(database) {
  return http.createServer(async (req, res) => {
    try { const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`); if (url.pathname.startsWith('/api/')) await routeApi(database, req, res, url); else if (url.pathname.startsWith('/storage/')) fail(res, 404, 'Not found'); else serveStatic(req, res, url.pathname); }
    catch (error) { console.error(error); if (!res.headersSent) fail(res, error.code === 'BODY_TOO_LARGE' ? 413 : 500, error.code === 'INVALID_JSON' ? 'Request body valid JSON नहीं है।' : 'Server error आया।'); else res.end(); }
  });
}

const db = openDatabase(DB_FILE);
const server = createServer(db);
if (require.main === module) server.listen(PORT, () => console.log(`MKRAAJLTP backend running at http://localhost:${PORT}`));
module.exports = { server, db, createServer, close: () => { server.close(); closeDatabase(db); } };
