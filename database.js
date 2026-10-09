const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = process.env.DB_PATH || path.join(DATA_DIR, 'app.sqlite');
const SCHEMA_FILE = path.join(ROOT, 'database', 'schema.sql');

function id(prefix = 'id') { return `${prefix}_${crypto.randomUUID()}`; }
function now() { return new Date().toISOString(); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  if (typeof password !== 'string' || password.length < 1) throw new Error('Password required');
  return { hash: crypto.scryptSync(password, salt, 64).toString('hex'), salt };
}
function verifyPassword(password, record) {
  if (!record?.password_hash && !record?.passwordHash) return false;
  try {
    const salt = record.password_salt || record.passwordSalt;
    const expected = Buffer.from(record.password_hash || record.passwordHash, 'hex');
    const candidate = crypto.scryptSync(String(password || ''), salt, 64);
    return expected.length === candidate.length && crypto.timingSafeEqual(candidate, expected);
  } catch { return false; }
}
function parseJson(value, fallback) {
  try { return JSON.parse(value); } catch { return fallback; }
}
function transaction(db, work) {
  db.exec('BEGIN IMMEDIATE');
  try { const value = work(); db.exec('COMMIT'); return value; }
  catch (error) { try { db.exec('ROLLBACK'); } catch {} throw error; }
}

const SSC = [
  ['General Awareness','Indian Polity','Easy','भारतीय संविधान में मौलिक अधिकार किस भाग में दिए गए हैं?',['भाग I','भाग II','भाग III','भाग IV'],2,'मौलिक अधिकार संविधान के भाग III में हैं।'],
  ['General Awareness','Indian Polity','Medium','धन विधेयक भारत की संसद में सबसे पहले किस सदन में प्रस्तुत होता है?',['राज्यसभा','लोकसभा','किसी भी सदन में','संयुक्त बैठक में'],1,'धन विधेयक केवल लोकसभा में प्रस्तुत किया जाता है।'],
  ['General Awareness','Science','Easy','विटामिन C की कमी से कौन-सा रोग होता है?',['रिकेट्स','स्कर्वी','बेरी-बेरी','रातांधता'],1,'विटामिन C की कमी से स्कर्वी होता है।'],
  ['General Awareness','Science','Medium','ध्वनि निर्वात में क्यों नहीं चल सकती?',['उसमें प्रकाश नहीं है','माध्यम के कण नहीं हैं','तापमान कम है','दाब बहुत अधिक है'],1,'ध्वनि को यांत्रिक तरंग के रूप में माध्यम के कणों की जरूरत होती है।'],
  ['General Awareness','Geography','Easy','भारत में मानसून की वापसी सामान्यतः किस दिशा से शुरू होती है?',['दक्षिण-पश्चिम','दक्षिण-पूर्व','उत्तर-पश्चिम','उत्तर-पूर्व'],2,'दक्षिण-पश्चिम मानसून की वापसी उत्तर-पश्चिम भारत से शुरू होती है।'],
  ['General Awareness','History','Easy','अशोक के अधिकांश शिलालेख किस लिपि में लिखे गए थे?',['ब्राह्मी','देवनागरी','फारसी','ग्रंथ'],0,'अधिकांश अशोक शिलालेख ब्राह्मी लिपि में हैं।'],
  ['Reasoning','Analogy','Easy','Book : Read :: Food : ?',['Cook','Eat','Buy','Serve'],1,'Book को read किया जाता है और food को eat।'],
  ['Reasoning','Analogy','Medium','यदि CAT को DBU लिखा जाए, तो DOG को कैसे लिखा जाएगा?',['EPH','EOG','FPH','DPH'],0,'हर अक्षर में एक जोड़ने पर D-O-G से E-P-H मिलता है।'],
  ['Reasoning','Series','Easy','श्रृंखला 2, 4, 8, 16, ? में अगली संख्या क्या है?',['20','24','30','32'],3,'हर पद पिछले पद का दुगुना है।'],
  ['Reasoning','Coding-Decoding','Medium','यदि BLUE को EOXH लिखा जाए, तो हर अक्षर में कितना परिवर्तन हुआ है?',['+1','+2','+3','-1'],2,'B→E, L→O, U→X, E→H: प्रत्येक अक्षर में +3।'],
  ['Reasoning','Direction','Easy','कोई व्यक्ति उत्तर की ओर 5 मीटर और फिर दाएँ 3 मीटर चलता है। वह प्रारंभिक स्थान से किस दिशा में है?',['उत्तर-पश्चिम','उत्तर-पूर्व','दक्षिण-पूर्व','दक्षिण-पश्चिम'],1,'उत्तर के बाद दाएँ मुड़ना पूर्व है, इसलिए दिशा उत्तर-पूर्व।'],
  ['Reasoning','Blood Relation','Medium','रीना, मोहन की बहन है और मोहन, सीमा का पुत्र है। रीना का सीमा से क्या संबंध है?',['बहन','पुत्री','माता','भतीजी'],1,'मोहन की बहन रीना, सीमा की पुत्री है।'],
  ['Quantitative Aptitude','Percentage','Easy','200 का 15% कितना होगा?',['15','20','30','35'],2,'200 × 15/100 = 30।'],
  ['Quantitative Aptitude','Percentage','Medium','किसी संख्या में 20% वृद्धि के बाद वह 240 हो जाती है। मूल संख्या क्या थी?',['180','200','210','220'],1,'मूल संख्या × 1.20 = 240, इसलिए मूल संख्या 200 है।'],
  ['Quantitative Aptitude','Ratio','Easy','3:5 के अनुपात में 64 को बाँटने पर छोटा भाग कितना होगा?',['20','24','30','40'],1,'कुल 8 भाग; छोटा भाग 64 × 3/8 = 24।'],
  ['Quantitative Aptitude','Average','Easy','4 और 10 का औसत क्या है?',['5','6','7','8'],2,'(4 + 10)/2 = 7।'],
  ['Quantitative Aptitude','Profit and Loss','Medium','किसी वस्तु का क्रय मूल्य 500 रुपये और विक्रय मूल्य 575 रुपये है। लाभ प्रतिशत क्या है?',['10%','12%','15%','20%'],2,'लाभ 75; 75/500 × 100 = 15%।'],
  ['English','Vocabulary','Easy','Choose the synonym of “Rapid”.',['Slow','Quick','Weak','Late'],1,'Rapid का अर्थ quick या तेज़ होता है।'],
  ['English','Grammar','Easy','Choose the correctly spelled word.',['Accomodation','Accommodation','Acommodation','Accommadation'],1,'Accommodation सही spelling है।'],
  ['English','Grammar','Medium','Fill in the blank: She has lived here ___ 2020.',['for','from','since','by'],2,'किसी निश्चित समय-बिंदु के साथ since प्रयुक्त होता है।'],
  ['English','Reading','Medium','Choose the antonym of “Ancient”.',['Old','Modern','Historic','Early'],1,'Ancient का विलोम modern है।']
];
const UPSC = [
  ['Polity','Fundamental Rights','Medium','अनुच्छेद 32 को संविधान की “आत्मा” और “हृदय” किसने कहा था?',['महात्मा गांधी','डॉ. बी. आर. आंबेडकर','जवाहरलाल नेहरू','सरदार पटेल'],1,'डॉ. आंबेडकर ने अनुच्छेद 32 के महत्व को इस प्रकार बताया था।'],
  ['Polity','Parliament','Medium','भारत में मंत्रिपरिषद सामूहिक रूप से किसके प्रति उत्तरदायी है?',['राष्ट्रपति','राज्यसभा','लोकसभा','सर्वोच्च न्यायालय'],2,'अनुच्छेद 75 के अनुसार मंत्रिपरिषद लोकसभा के प्रति सामूहिक रूप से उत्तरदायी है।'],
  ['Polity','Constitution','Easy','संविधान की प्रस्तावना में “समाजवादी” और “पंथनिरपेक्ष” शब्द किस संशोधन से जोड़े गए?',['24वाँ','42वाँ','44वाँ','73वाँ'],1,'42वें संविधान संशोधन अधिनियम, 1976 से ये शब्द जोड़े गए।'],
  ['Geography','Indian Rivers','Medium','निम्न में से कौन-सी नदी पश्चिम की ओर बहती है?',['गोदावरी','कृष्णा','नर्मदा','महानदी'],2,'नर्मदा पश्चिम की ओर बहकर अरब सागर में मिलती है।'],
  ['Geography','Monsoon','Medium','भारतीय ग्रीष्मकालीन मानसून की प्रमुख शाखाएँ कौन-सी हैं?',['अरब सागर और बंगाल की खाड़ी','हिंद महासागर और प्रशांत','अटलांटिक और अरब सागर','बंगाल और भूमध्यसागर'],0,'दक्षिण-पश्चिम मानसून अरब सागर और बंगाल की खाड़ी शाखाओं में बाँटा जाता है।'],
  ['Geography','Soils','Easy','काली मिट्टी किस फसल के लिए विशेष रूप से उपयुक्त मानी जाती है?',['कपास','चाय','जूट','केसर'],0,'काली मिट्टी की नमी धारण क्षमता कपास के लिए उपयोगी है।'],
  ['History','Modern India','Easy','भारतीय राष्ट्रीय कांग्रेस की स्थापना किस वर्ष हुई?',['1885','1905','1857','1947'],0,'भारतीय राष्ट्रीय कांग्रेस की स्थापना 1885 में हुई थी।'],
  ['History','Modern India','Medium','स्थायी बंदोबस्त 1793 में किस गवर्नर-जनरल से संबंधित है?',['लॉर्ड डलहौजी','लॉर्ड कॉर्नवालिस','लॉर्ड कर्जन','वॉरेन हेस्टिंग्स'],1,'लॉर्ड कॉर्नवालिस ने 1793 में स्थायी बंदोबस्त लागू किया।'],
  ['History','Ancient India','Medium','बौद्ध धर्म के अष्टांगिक मार्ग में निम्न में से कौन शामिल है?',['सम्यक दृष्टि','राजसूय यज्ञ','अश्वमेध','दिग्विजय'],0,'सम्यक दृष्टि अष्टांगिक मार्ग का एक अंग है।'],
  ['Economy','Inflation','Easy','महंगाई का सबसे सामान्य अर्थ क्या है?',['कीमतों में सामान्य वृद्धि','उत्पादन में वृद्धि','करों में कमी','निर्यात में वृद्धि'],0,'Inflation सामान्य मूल्य स्तर में लगातार वृद्धि है।'],
  ['Economy','National Income','Medium','GDP किस अवधि में उत्पादित अंतिम वस्तुओं और सेवाओं का मूल्य मापता है?',['एक निश्चित अवधि','केवल एक दिन','केवल विदेशी उत्पादन','केवल सरकारी उत्पादन'],0,'GDP एक निश्चित अवधि में घरेलू सीमा के भीतर अंतिम उत्पादन का मूल्य है।'],
  ['Environment','Biodiversity','Easy','जैव विविधता का सबसे व्यापक अर्थ क्या है?',['केवल पेड़ों की संख्या','जीवों और पारिस्थितिक तंत्रों की विविधता','केवल पशुधन','केवल समुद्री जीवन'],1,'जैव विविधता में जीन, प्रजाति और पारिस्थितिकी तंत्र स्तर की विविधता आती है।']
];

function addQuestion(db, exam, row) {
  const [subject, topic, difficulty, stem, options, correct, explanation] = row;
  const questionId = id('q');
  db.prepare(`INSERT INTO questions
    (id,exam,subject,topic,difficulty,year,type,stem,options_json,correct_index,explanation,source,published,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?)`).run(questionId, exam, subject, topic, difficulty, null, 'MCQ', stem, JSON.stringify(options), correct, explanation, 'Original practice question — not a previous-year paper', now());
  return questionId;
}
function seedCatalogAndBank(db) {
  if (db.prepare('SELECT COUNT(*) AS count FROM exams').get().count > 0) return;
  const timestamp = now();
  db.prepare('INSERT INTO exams (id,code,name,description,active) VALUES (?,?,?,?,1)').run(id('exam'), 'SSC', 'SSC Examinations', 'Original practice for SSC learners.',);
  db.prepare('INSERT INTO exams (id,code,name,description,active) VALUES (?,?,?,?,1)').run(id('exam'), 'UPSC', 'UPSC Civil Services', 'Original practice for UPSC learners.',);
  const subjects = {
    SSC: ['General Awareness','Reasoning','Quantitative Aptitude','English'],
    UPSC: ['Polity','Geography','History','Economy','Environment']
  };
  for (const [exam, names] of Object.entries(subjects)) for (const name of names) {
    db.prepare('INSERT INTO subjects (id,exam_code,name,active) VALUES (?,?,?,1)').run(id('subject'), exam, name);
  }
  const topics = new Set();
  for (const [exam, rows] of [['SSC', SSC], ['UPSC', UPSC]]) for (const row of rows) topics.add(`${exam}\u0000${row[0]}\u0000${row[1]}`);
  for (const item of topics) { const [exam, subject, topic] = item.split('\u0000'); db.prepare('INSERT INTO topics (id,exam_code,subject_name,name,active) VALUES (?,?,?,?,1)').run(id('topic'), exam, subject, topic); }
  db.prepare('INSERT INTO courses (id,title,exam_code,level,lessons,premium,description) VALUES (?,?,?,?,?,?,?)').run(id('course'), 'SSC Original Practice Path', 'SSC', 'Beginner', 0, 0, 'A bank-first path using original practice questions.');
  db.prepare('INSERT INTO courses (id,title,exam_code,level,lessons,premium,description) VALUES (?,?,?,?,?,?,?)').run(id('course'), 'UPSC Foundation Practice Path', 'UPSC', 'Beginner', 0, 0, 'A bank-first path using original practice questions.');
  const questionIds = { SSC: SSC.map((row) => addQuestion(db, 'SSC', row)), UPSC: UPSC.map((row) => addQuestion(db, 'UPSC', row)) };
  const createTest = (exam, title, category, ids, duration) => {
    const testId = id('test');
    db.prepare(`INSERT INTO tests (id,title,exam,category,description,duration_minutes,positive_marking,negative_marking,published,premium,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,1,0,?,?)`).run(testId, title, exam, category, 'Original practice set; not a previous-year paper.', duration, 2, exam === 'UPSC' ? 2 / 3 : 0.5, timestamp, timestamp);
    ids.forEach((questionId, position) => db.prepare('INSERT INTO test_questions (test_id,question_id,position) VALUES (?,?,?)').run(testId, questionId, position));
  };
  createTest('SSC', 'SSC Full Length Original Practice 01', 'Full Length Mock Test', questionIds.SSC, 30);
  createTest('SSC', 'SSC General Awareness Sprint', 'Subject Test', questionIds.SSC.slice(0, 6), 15);
  createTest('SSC', 'SSC Analogy Drill', 'Topic Test', questionIds.SSC.slice(6, 8), 8);
  createTest('SSC', 'SSC Daily Original Practice', 'Daily Test', questionIds.SSC.slice(0, 5), 10);
  createTest('SSC', 'SSC Weekly Revision Practice', 'Weekly Test', questionIds.SSC.slice(5, 16), 20);
  createTest('UPSC', 'UPSC GS Original Practice 01', 'Full Length Mock Test', questionIds.UPSC, 25);
  createTest('UPSC', 'UPSC Polity and Geography Sprint', 'Subject Test', questionIds.UPSC.slice(0, 6), 15);
}
function openDatabase(file = DB_FILE) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;');
  try { if (file !== ':memory:') fs.chmodSync(file, 0o600); } catch {}
  db.exec(fs.readFileSync(SCHEMA_FILE, 'utf8'));
  transaction(db, () => seedCatalogAndBank(db));
  return db;
}
function closeDatabase(db) { try { db.close(); } catch {} }

module.exports = { DATA_DIR, DB_FILE, SCHEMA_FILE, id, now, hashPassword, verifyPassword, parseJson, transaction, openDatabase, closeDatabase };
