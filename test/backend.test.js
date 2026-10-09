const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const temp = fs.mkdtempSync(path.join(process.cwd(), '.backend-test-'));
process.env.DB_PATH = path.join(temp, 'app.sqlite');
process.env.UPLOAD_DIR = path.join(temp, 'uploads');
process.env.NODE_ENV = 'test';
const { server, db } = require('../server');
const { id, now, hashPassword } = require('../database');

let base;
let studentCookie;
let adminCookie;
function cookieFrom(response) { return response.headers.get('set-cookie')?.split(';')[0]; }
async function request(method, route, body, cookie, extra = {}) {
  const response = await fetch(`${base}${route}`, { method, headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(cookie ? { cookie } : {}), ...extra }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let data; try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { response, data };
}

test.before(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  const credentials = hashPassword('AdminPassword!2026');
  const userId = id('admin'); const timestamp = now();
  db.prepare('INSERT INTO users (id,name,email,password_hash,password_salt,role,exam,created_at) VALUES (?,?,?,?,?,?,?,?)').run(userId, 'Test Admin', 'admin@test.local', credentials.hash, credentials.salt, 'admin', 'SSC', timestamp);
  db.prepare('INSERT INTO admins (user_id,permissions,created_at) VALUES (?,?,?)').run(userId, '[]', timestamp);
});
test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.close();
  fs.rmSync(temp, { recursive: true, force: true });
});

test('public catalog has honest original bank and no seeded account', async () => {
  const catalog = await request('GET', '/api/catalog');
  assert.equal(catalog.response.status, 200);
  const bank = db.prepare('SELECT COUNT(*) AS n FROM questions').get().n;
  assert.ok(bank >= 32);
  const current = db.prepare('SELECT COUNT(*) AS n FROM current_affairs').get().n;
  assert.equal(current, 0);
  const predictable = db.prepare("SELECT COUNT(*) AS n FROM users WHERE email IN ('admin@mkraajltp.in','student@mkraajltp.in')").get().n;
  assert.equal(predictable, 0);
  assert.ok(catalog.data.subjects.length > 0);
});

test('student registration, secure session, owner-scoped timed attempt and authoritative scoring', async () => {
  let result = await request('GET', '/api/me');
  assert.deepEqual(result.data, { user: null });
  result = await request('POST', '/api/auth/register', { name: 'Asha Student', email: 'asha@test.local', password: 'StrongPass!2026', exam: 'SSC' });
  assert.equal(result.response.status, 201);
  studentCookie = cookieFrom(result.response);
  assert.match(result.response.headers.get('set-cookie'), /HttpOnly/);
  assert.match(result.response.headers.get('set-cookie'), /SameSite=Strict/);
  assert.doesNotMatch(result.response.headers.get('set-cookie'), /Secure/);
  result = await request('GET', '/api/dashboard', undefined, studentCookie);
  assert.equal(result.response.status, 200);
  assert.equal(result.data.stats.testsCompleted, 0);
  assert.equal(result.data.rank, null);
  assert.match(result.data.plan.headline, /assessment/);

  result = await request('POST', '/api/auth/login', { email: 'asha@test.local', password: 'StrongPass!2026', role: 'admin' });
  assert.equal(result.response.status, 401);
  result = await request('GET', '/api/tests?exam=SSC', undefined, studentCookie);
  assert.equal(result.response.status, 200);
  assert.ok(result.data.tests.length > 0);
  const testId = result.data.tests[0].id;
  result = await request('POST', `/api/tests/${testId}/start`, {}, studentCookie);
  assert.equal(result.response.status, 201);
  const attempt = result.data.attempt;
  assert.ok(attempt.deadlineAt);
  const firstQuestion = result.data.test.questions[0];
  assert.equal(Object.prototype.hasOwnProperty.call(firstQuestion, 'correctIndex'), false);
  result = await request('PUT', `/api/attempts/${attempt.id}/answers`, { answers: { [firstQuestion.id]: '0' }, review: [] }, studentCookie);
  assert.equal(result.response.status, 400);
  result = await request('PUT', `/api/attempts/${attempt.id}/answers`, { answers: { [firstQuestion.id]: 0 }, review: [firstQuestion.id] }, studentCookie);
  assert.equal(result.response.status, 200);
  result = await request('GET', `/api/attempts/${attempt.id}`, undefined, studentCookie);
  assert.equal(result.response.status, 200);
  assert.equal(result.data.attempt.answers[firstQuestion.id], 0);
  assert.deepEqual(result.data.attempt.review, [firstQuestion.id]);
  result = await request('POST', `/api/attempts/${attempt.id}/submit`, {}, studentCookie);
  assert.equal(result.response.status, 200);
  assert.equal(typeof result.data.result.score, 'number');
  result = await request('POST', `/api/attempts/${attempt.id}/submit`, {}, studentCookie);
  assert.equal(result.response.status, 200);
  assert.equal(result.data.result.attemptId, attempt.id);
  result = await request('GET', `/api/results/${attempt.id}`, undefined, studentCookie);
  assert.equal(result.response.status, 200);
  assert.equal(result.data.result.questions.length, result.data.result.totalQuestions);
  assert.equal(result.data.result.questions[0].question.explanation !== undefined, true);
  result = await request('POST', '/api/tests/custom', { exam: 'SSC', subject: 'Reasoning', count: 2, durationMinutes: 5, title: 'My small test' }, studentCookie);
  assert.equal(result.response.status, 201);
  assert.equal(result.data.test.ownerUserId, undefined);
  const customTestId = result.data.test.id;
  result = await request('GET', `/api/tests?exam=SSC`, undefined, studentCookie);
  assert.ok(result.data.tests.some((item) => item.id === customTestId));
  result = await request('GET', '/api/daily-quiz', undefined, studentCookie);
  assert.equal(result.response.status, 200);
  assert.ok(result.data.test.id);
  result = await request('POST', `/api/tests/${result.data.test.id}/start`, {}, studentCookie);
  assert.equal(result.response.status, 201);
  result = await request('POST', '/api/auth/register', { name: 'Other Student', email: 'other@test.local', password: 'OtherStrong!2026', exam: 'SSC' });
  const otherCookie = cookieFrom(result.response);
  result = await request('GET', `/api/tests/${customTestId}`, undefined, otherCookie);
  assert.equal(result.response.status, 404);
});

test('admin content remains private until publish and students cannot access admin routes', async () => {
  let result = await request('GET', '/api/admin/stats', undefined, studentCookie);
  assert.equal(result.response.status, 403);
  result = await request('POST', '/api/auth/login', { email: 'admin@test.local', password: 'AdminPassword!2026', role: 'admin' });
  assert.equal(result.response.status, 200);
  adminCookie = cookieFrom(result.response);
  const attemptedQuestionId = db.prepare('SELECT question_id FROM attempt_questions LIMIT 1').get().question_id;
  result = await request('PATCH', `/api/admin/questions/${attemptedQuestionId}`, { stem: 'Must not rewrite an attempted question' }, adminCookie);
  assert.equal(result.response.status, 409);
  const stem = 'Admin-only unpublished practice question';
  result = await request('POST', '/api/admin/questions', { exam: 'SSC', subject: 'Reasoning', topic: 'Series', difficulty: 'Easy', stem, options: ['A', 'B'], correctIndex: 0, explanation: 'Original explanation', published: false }, adminCookie);
  assert.equal(result.response.status, 201);
  const questionId = result.data.question.id;
  result = await request('GET', `/api/questions?q=${encodeURIComponent(stem)}`, undefined, studentCookie);
  assert.equal(result.response.status, 200);
  assert.equal(result.data.questions.some((question) => question.id === questionId), false);
  result = await request('POST', '/api/admin/materials', { title: 'Private notes', exam: 'SSC', content: 'admin-only text', published: false }, adminCookie);
  assert.equal(result.response.status, 201);
  const materialId = result.data.material.id;
  result = await request('PATCH', `/api/admin/materials/${materialId}`, { published: true, premium: true }, adminCookie);
  assert.equal(result.response.status, 200);
  result = await request('GET', '/api/materials', undefined, studentCookie);
  assert.equal(result.data.materials.some((item) => item.id === materialId), false);
  result = await request('GET', `/api/materials/${materialId}`, undefined, studentCookie);
  assert.equal(result.response.status, 403);
  result = await request('POST', '/api/admin/materials', { title: 'Bad upload', exam: 'SSC', fileName: 'bad.pdf', fileData: Buffer.from('not pdf').toString('base64') }, adminCookie);
  assert.equal(result.response.status, 400);
});
