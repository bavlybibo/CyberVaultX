const pptxgen = require('pptxgenjs');

function loadLayoutHelpers() {
  try {
    return require('./pptx_layout_helpers.js');
  } catch (_err) {
    return {
      warnIfSlideHasOverlaps: () => undefined,
      warnIfSlideElementsOutOfBounds: () => undefined,
    };
  }
}

const { warnIfSlideHasOverlaps, warnIfSlideElementsOutOfBounds } = loadLayoutHelpers();

const pptx = new pptxgen();
pptx.layout = 'LAYOUT_WIDE';
pptx.author = 'CyberVault X Team';
pptx.subject = 'Secure Password Manager with Local Encryption at Rest';
pptx.title = 'CyberVault X Presentation';
pptx.company = 'Elsewedy University of Technology';
pptx.lang = 'en-US';
pptx.theme = {
  headFontFace: 'Aptos Display',
  bodyFontFace: 'Aptos',
  lang: 'en-US'
};
pptx.defineLayout({ name: 'CUSTOM_WIDE', width: 13.333, height: 7.5 });
pptx.layout = 'CUSTOM_WIDE';
pptx.margin = 0;

const C = {
  navy: '102033',
  blue: '173B5F',
  teal: '0E7490',
  cyan: '06B6D4',
  green: '16A34A',
  orange: 'EA580C',
  red: 'DC2626',
  slate: '475467',
  light: 'F8FAFC',
  card: 'FFFFFF',
  line: 'D0D5DD',
  darkLine: '344054',
};

function addHeader(slide, title, kicker='CyberVault X') {
  slide.background = { color: 'FFFFFF' };
  slide.addText(kicker, { x:0.55, y:0.32, w:2.7, h:0.25, fontFace:'Aptos', fontSize:8, color:C.teal, bold:true, margin:0 });
  slide.addText(title, { x:0.55, y:0.62, w:10.9, h:0.48, fontFace:'Aptos Display', fontSize:24, bold:true, color:C.navy, margin:0.02, breakLine:false, fit:'shrink' });
  slide.addShape(pptx.ShapeType.line, { x:0.55, y:1.22, w:12.2, h:0, line:{ color:C.line, width:0.8 } });
  slide.addText('v5.7.2', { x:11.85, y:0.34, w:0.85, h:0.24, fontSize:8, color:C.slate, align:'right', margin:0 });
}
function tag(slide, text, x,y,w, color=C.teal) {
  slide.addText(text, { x,y,w,h:0.34, fontSize:8.5, bold:true, color:color, align:'center', valign:'mid', margin:0.03, fill:{color:'ECFEFF'}, line:{color:'BAE6FD', width:0.6}, radius:0.12 });
}
function box(slide, title, body, x,y,w,h, accent=C.teal) {
  slide.addText(title, { x, y, w, h:0.35, fontSize:13, bold:true, color:C.navy, margin:0.06, breakLine:false, fit:'shrink' });
  slide.addText(body, { x, y:y+0.44, w, h:h-0.44, fontSize:10.2, color:C.slate, margin:0.06, fit:'shrink' });
  slide.addShape(pptx.ShapeType.line, { x, y:y+h+0.02, w, h:0, line:{ color:accent, width:2 } });
}
function metric(slide, value, label, x,y,w, color=C.blue) {
  slide.addText(value, { x,y,w,h:0.52, fontSize:22, bold:true, color:color, align:'center', margin:0.02, fit:'shrink' });
  slide.addText(label, { x, y:y+0.55, w, h:0.35, fontSize:8.8, color:C.slate, align:'center', margin:0.02, fit:'shrink' });
}
function check(slide, text, x, y, w, color=C.green) {
  slide.addText('✓', { x, y, w:0.22, h:0.22, fontSize:11, bold:true, color:color, margin:0 });
  slide.addText(text, { x:x+0.28, y:y-0.01, w, h:0.3, fontSize:9.5, color:C.slate, margin:0.02, fit:'shrink' });
}
function finalCheck(slide) {
  warnIfSlideHasOverlaps(slide, pptx, { ignoreLines:true, ignoreDecorativeShapes:true, muteContainment:true });
  warnIfSlideElementsOutOfBounds(slide, pptx);
}

// Slide 1
let s = pptx.addSlide();
s.background = { color: 'FFFFFF' };
s.addImage({ path:'assets/app_icon.png', x:0.7, y:0.55, w:0.82, h:0.82 });
s.addText('CyberVault X', { x:0.7, y:1.65, w:5.8, h:0.7, fontSize:36, bold:true, color:C.navy, margin:0 });
s.addText('Secure Password Manager with Local Encryption at Rest', { x:0.74, y:2.42, w:5.9, h:0.35, fontSize:15, color:C.slate, margin:0 });
s.addText('CET334 - Cryptographic Algorithms & Protocols', { x:0.74, y:2.93, w:5.4, h:0.25, fontSize:10.5, color:C.teal, bold:true, margin:0 });
s.addImage({ path:'assets/splash.png', x:7.75, y:0.85, w:4.75, h:3.65 });
tag(s, 'Local-first', 0.74, 5.25, 1.2);
tag(s, 'AES-GCM', 2.1, 5.25, 1.1);
tag(s, 'PBKDF2', 3.35, 5.25, 1.1);
tag(s, 'AI-style Local Security Coach', 4.6, 5.25, 1.35);
s.addText('Professional release package: source code, tests, final report, presentation deck, and live demo plan.', { x:0.74, y:6.25, w:11.5, h:0.3, fontSize:11, color:C.slate, margin:0 });
finalCheck(s);

// Slide 2
s = pptx.addSlide(); addHeader(s, 'Problem & market need');
s.addText('Password reuse turns one leaked account into many compromised accounts.', { x:0.65, y:1.55, w:6.3, h:0.9, fontSize:24, bold:true, color:C.navy, margin:0.02, fit:'shrink' });
box(s, 'The user problem', 'People save many passwords, reuse weak patterns, and rarely know which accounts are risky.', 0.7, 3.0, 3.7, 1.0, C.red);
box(s, 'The security problem', 'A plaintext or weak vault becomes a single point of failure. The vault must protect secrets even if the database is copied.', 4.75, 3.0, 3.7, 1.0, C.orange);
box(s, 'The academic problem', 'The project must prove real cryptographic implementation, working code, documentation, and live demo readiness.', 8.8, 3.0, 3.7, 1.0, C.teal);
metric(s, '100+', 'online accounts per user', 0.85, 5.45, 2.3, C.blue);
metric(s, '0', 'cloud uploads required', 3.75, 5.45, 2.3, C.teal);
metric(s, '1', 'local encrypted vault', 6.65, 5.45, 2.3, C.green);
metric(s, '20/20', 'target presentation grade', 9.55, 5.45, 2.3, C.orange);
finalCheck(s);

// Slide 3
s = pptx.addSlide(); addHeader(s, 'Solution overview');
s.addText('CyberVault X is a local encrypted password manager with security intelligence built around the vault.', { x:0.65, y:1.45, w:11.8, h:0.38, fontSize:16, color:C.slate, margin:0.02 });
box(s, 'Encrypted Vault', 'AES-GCM encrypted credential fields stored locally in SQLite.', 0.75, 2.25, 3.4, 1.2, C.blue);
box(s, 'Security Center', 'Weak, reused, breached, stale, and metadata risk analysis.', 4.95, 2.25, 3.4, 1.2, C.orange);
box(s, 'AI-style Local Security Coach', 'Local deterministic advisor that turns findings into priority actions.', 9.15, 2.25, 3.4, 1.2, C.teal);
box(s, 'Proof Center', 'Verifies encrypted schema, audit chain, backup preview, and report package hashes.', 0.75, 4.5, 3.4, 1.2, C.green);
box(s, 'Report Package', 'Privacy-safe executive report, audit log, AI summary, and manifest.', 4.95, 4.5, 3.4, 1.2, C.blue);
box(s, 'Release Ready', 'Tests, build script, preflight checks, final report, and presentation deck.', 9.15, 4.5, 3.4, 1.2, C.orange);
finalCheck(s);

// Slide 4
s = pptx.addSlide(); addHeader(s, 'Architecture');
// connectors first
s.addShape(pptx.ShapeType.line, { x:2.75, y:3.03, w:1.05, h:0, line:{color:C.darkLine, width:1.5, beginArrowType:'none', endArrowType:'triangle'} });
s.addShape(pptx.ShapeType.line, { x:5.15, y:3.03, w:1.05, h:0, line:{color:C.darkLine, width:1.5, endArrowType:'triangle'} });
s.addShape(pptx.ShapeType.line, { x:7.55, y:3.03, w:1.05, h:0, line:{color:C.darkLine, width:1.5, endArrowType:'triangle'} });
s.addShape(pptx.ShapeType.line, { x:9.95, y:3.03, w:1.05, h:0, line:{color:C.darkLine, width:1.5, endArrowType:'triangle'} });
const arch = [
  ['UI', 'Tkinter screens\nDialogs\nDemo flow', 0.65, C.teal],
  ['Manager', 'Vault actions\nSettings\nAuth state', 3.05, C.blue],
  ['Services', 'Backup\nReports\nAI-style Local Security Coach\nProof checks', 5.45, C.orange],
  ['Crypto', 'AES-GCM\nPBKDF2\nSHA hashes', 7.85, C.green],
  ['SQLite', 'Encrypted rows\nHistory\nAudit log', 10.25, C.navy],
];
arch.forEach(([title,body,x,color])=>{
  s.addText(title, {x, y:2.22, w:1.75, h:0.42, fontSize:14, bold:true, color:C.navy, align:'center', margin:0.04, fill:{color:'F8FAFC'}, line:{color, width:1.1}});
  s.addText(body, {x, y:2.78, w:1.75, h:1.08, fontSize:9, color:C.slate, align:'center', valign:'mid', margin:0.06, fill:{color:'FFFFFF'}, line:{color:C.line, width:0.8}, fit:'shrink'});
});
check(s, 'Service separation keeps crypto/database logic reusable if UI is migrated to PyQt5.', 0.85, 5.0, 8.5);
check(s, 'All vault analysis is local; no raw secrets are sent to external services.', 0.85, 5.4, 8.5);
check(s, 'Release preflight validates structure, docs, dependency readiness, and breach-list format.', 0.85, 5.8, 8.5);
finalCheck(s);

// Slide 5
s = pptx.addSlide(); addHeader(s, 'Cryptographic workflow');
// connectors first
s.addShape(pptx.ShapeType.line, { x:2.4, y:3.2, w:1.2, h:0, line:{color:C.darkLine, width:1.4, endArrowType:'triangle'} });
s.addShape(pptx.ShapeType.line, { x:5.0, y:3.2, w:1.2, h:0, line:{color:C.darkLine, width:1.4, endArrowType:'triangle'} });
s.addShape(pptx.ShapeType.line, { x:7.6, y:3.2, w:1.2, h:0, line:{color:C.darkLine, width:1.4, endArrowType:'triangle'} });
s.addShape(pptx.ShapeType.line, { x:10.2, y:3.2, w:1.0, h:0, line:{color:C.darkLine, width:1.4, endArrowType:'triangle'} });
const steps = [
  ['Master password', 'Never stored directly', 0.7],
  ['PBKDF2-SHA256', 'Derives vault key', 3.3],
  ['AES-GCM', 'Encrypts fields', 5.9],
  ['AAD binding', 'Credential + field context', 8.5],
  ['SQLite', 'Nonce/cipher pairs', 11.0],
];
steps.forEach(([title,body,x])=>{
  s.addText(title, {x, y:2.55, w:1.75, h:0.35, fontSize:11.5, bold:true, color:C.navy, align:'center', margin:0.03, fill:{color:'ECFEFF'}, line:{color:C.teal, width:1}});
  s.addText(body, {x, y:3.05, w:1.75, h:0.6, fontSize:8.8, color:C.slate, align:'center', valign:'mid', margin:0.04, fill:{color:'FFFFFF'}, line:{color:C.line, width:0.8}, fit:'shrink'});
});
box(s, 'Why this matters', 'The database can be copied, but encrypted credential fields remain protected without the master password. AES-GCM also rejects tampered ciphertext.', 0.9, 5.05, 5.2, 1.05, C.green);
box(s, 'Demo proof', 'Security Proof Center checks encrypted schema, AAD migration status, audit-chain validity, and report integrity.', 7.1, 5.05, 5.2, 1.05, C.blue);
finalCheck(s);

// Slide 6
s = pptx.addSlide(); addHeader(s, 'Core requirement coverage');
const reqs = [
  ['Encrypted Password Vault', 'AES-GCM field encryption, local SQLite, encrypted history'],
  ['Master Password', 'PBKDF2-SHA256, policy validation, unlock throttling'],
  ['Generator', 'Configurable length/classes, entropy feedback, presets'],
  ['Offline Demo Breach-Subset Check', 'Offline SHA1 dataset with local lookup'],
  ['Strength Analysis', 'Weak/reused/breached/stale score and recommendations'],
];
reqs.forEach((r,i)=>{
  const y = 1.55 + i*0.78;
  s.addText(r[0], {x:0.8, y, w:3.1, h:0.36, fontSize:12.2, bold:true, color:C.navy, margin:0.04, fit:'shrink'});
  s.addText(r[1], {x:4.25, y:y+0.02, w:7.9, h:0.34, fontSize:10.2, color:C.slate, margin:0.02, fit:'shrink'});
  s.addShape(pptx.ShapeType.line, {x:0.8, y:y+0.5, w:11.6, h:0, line:{color:C.line, width:0.65}});
});
finalCheck(s);

// Slide 7
s = pptx.addSlide(); addHeader(s, 'Product-grade upgrades');
box(s, 'AI-style Local Security Coach', 'Local advisor: priority queue, attacker view, fix path, business impact, and projected score gain.', 0.75, 1.7, 3.55, 1.25, C.teal);
box(s, 'Security Proof Center', 'One place to prove crypto posture, audit-chain validity, backup preview, and report verification.', 4.9, 1.7, 3.55, 1.25, C.green);
box(s, 'Tamper evidence', 'Audit events use previous-hash and event-hash linkage to expose log modification.', 9.05, 1.7, 3.55, 1.25, C.orange);
box(s, 'Encrypted backup', 'Preview restore impact, handle duplicates, rollback on failure, and keep backup metadata versioned.', 0.75, 4.3, 3.55, 1.25, C.blue);
box(s, 'Report package', 'Exports HTML reports, AI summary, manifest hashes, and local signature verification.', 4.9, 4.3, 3.55, 1.25, C.red);
box(s, 'Release preflight', 'Validates docs, tests, structure, dataset format, and presentation assets before packaging.', 9.05, 4.3, 3.55, 1.25, C.teal);
finalCheck(s);

// Slide 8
s = pptx.addSlide(); addHeader(s, 'Testing & validation');
s.addText('Testing proves that the app is more than a UI demo.', { x:0.7, y:1.5, w:7.5, h:0.4, fontSize:17, bold:true, color:C.navy, margin:0.02 });
check(s, 'AES-GCM backup roundtrip and wrong-passphrase failure', 1.0, 2.25, 6.25);
check(s, 'AAD blocks encrypted-field swaps between records/fields', 1.0, 2.7, 6.25);
check(s, 'Backup import rolls back if validation fails mid-transaction', 1.0, 3.15, 6.25);
check(s, 'Report package verifier detects tampered artifacts', 1.0, 3.6, 6.25);
check(s, 'AI-style Local Security Coach payloads are redacted and privacy-safe', 1.0, 4.05, 6.25);
check(s, 'Release preflight checks final submission assets', 1.0, 4.5, 6.25);
s.addText('Commands', { x:8.4, y:2.22, w:3.0, h:0.25, fontSize:11.5, bold:true, color:C.navy, margin:0 });
s.addText('python -m pytest -q tests\npython tools/release_preflight.py\nbuild_release.bat', { x:8.4, y:2.65, w:3.7, h:1.3, fontSize:11, color:C.slate, margin:0.08, fill:{color:'F2F4F7'}, line:{color:C.line, width:0.8}, fit:'shrink' });
metric(s, 'pass/fail', 'automated proof', 8.75, 4.75, 2.6, C.green);
finalCheck(s);

// Slide 9
s = pptx.addSlide(); addHeader(s, 'Live demo path');
const demo = [
  'Create or unlock vault', 'Create Assessment Workspace', 'Dashboard health score', 'Security Center findings', 'Generate AI-style Local Security Coach plan', 'Generate replacement password', 'Run Security Proof Center', 'Export and verify report package', 'Encrypted backup preview', 'Panic lock'
];
demo.forEach((t,i)=>{
  const col = i < 5 ? 0 : 1;
  const x = col === 0 ? 0.9 : 6.9;
  const y = 1.55 + (i%5)*0.82;
  s.addText(String(i+1).padStart(2,'0'), {x, y, w:0.52, h:0.42, fontSize:12, bold:true, color:'FFFFFF', align:'center', valign:'mid', margin:0, fill:{color: i<5 ? C.teal : C.blue}, line:{color:'FFFFFF', transparency:100}});
  s.addText(t, {x:x+0.72, y:y+0.04, w:4.55, h:0.34, fontSize:12, color:C.navy, margin:0.02, fit:'shrink'});
});
s.addText('Goal: show encryption, analysis, proof, reports, and safe failure handling in one smooth story.', {x:0.9, y:6.25, w:11.4, h:0.32, fontSize:11.5, color:C.slate, align:'center', margin:0.02});
finalCheck(s);

// Slide 10
s = pptx.addSlide(); addHeader(s, 'Honest limitations');
box(s, 'Breach database', 'Bundled file is a small offline demo subset. Future: custom import wizard or HIBP k-anonymity.', 0.8, 1.65, 3.55, 1.2, C.orange);
box(s, 'Runtime memory', 'Python cannot fully guarantee string zeroization. Auto-lock and clipboard clearing reduce exposure.', 4.9, 1.65, 3.55, 1.2, C.red);
box(s, 'Local manifest integrity signature', 'HMAC provides local manifest integrity. Future: Ed25519 public verification key for independent proof.', 9.0, 1.65, 3.55, 1.2, C.blue);
box(s, 'GUI toolkit', 'Tkinter improves portability. Service layers allow future PyQt5 migration if required.', 0.8, 4.25, 3.55, 1.2, C.teal);
box(s, 'Commercial-style academic readiness', 'Commercial-style academic prototype. Future production version needs external audit, installer signing, and secure-memory hardening.', 4.9, 4.25, 3.55, 1.2, C.green);
box(s, 'Screenshots', 'Real screenshots must be captured on the Windows demo machine after building the EXE.', 9.0, 4.25, 3.55, 1.2, C.orange);
finalCheck(s);

// Slide 11
s = pptx.addSlide(); addHeader(s, 'Final submission package');
s.addText('What the instructor receives', {x:0.8, y:1.55, w:5.0, h:0.35, fontSize:18, bold:true, color:C.navy, margin:0.02});
check(s, 'Source code with clear folders and requirements files', 1.0, 2.25, 6.3);
check(s, 'Automated tests and release preflight script', 1.0, 2.7, 6.3);
check(s, 'Final PDF report and markdown source', 1.0, 3.15, 6.3);
check(s, 'PowerPoint presentation deck', 1.0, 3.6, 6.3);
check(s, 'README, security model, privacy, limitation, and demo docs', 1.0, 4.05, 6.3);
check(s, 'GitHub plan showing team contribution split', 1.0, 4.5, 6.3);
check(s, 'Windows EXE and screenshots after local build', 1.0, 4.95, 6.3);
s.addText('Grade mapping', {x:8.2, y:1.75, w:3.1, h:0.35, fontSize:15, bold:true, color:C.navy, margin:0.02});
metric(s, '8', 'functionality', 8.05, 2.55, 1.45, C.green);
metric(s, '4', 'code/docs', 10.0, 2.55, 1.45, C.blue);
metric(s, '5', 'presentation', 8.05, 4.25, 1.45, C.orange);
metric(s, '3', 'Q&A', 10.0, 4.25, 1.45, C.teal);
finalCheck(s);

// Slide 12
s = pptx.addSlide();
s.background = { color:'102033' };
s.addImage({path:'assets/app_icon.png', x:0.75, y:0.65, w:0.85, h:0.85});
s.addText('CyberVault X', {x:0.75, y:1.85, w:5.4, h:0.65, fontSize:34, bold:true, color:'FFFFFF', margin:0});
s.addText('Local encryption. Practical security. Demo-ready proof.', {x:0.78, y:2.62, w:6.6, h:0.35, fontSize:16, color:'D1E7EF', margin:0});
s.addText('Q&A', {x:0.78, y:4.3, w:2.8, h:0.6, fontSize:26, bold:true, color:'FFFFFF', margin:0});
s.addText('Prepared answers cover AES-GCM, PBKDF2, AAD, offline demo breach-subset detection, AI-style Local Security Coach privacy, Tkinter choice, and project limitations.', {x:0.8, y:5.05, w:6.8, h:0.6, fontSize:12, color:'CBD5E1', margin:0.02, fit:'shrink'});
s.addImage({ path:'assets/splash.png', x:7.7, y:1.05, w:4.75, h:3.6 });
finalCheck(s);

pptx.writeFile({ fileName: 'presentation/CyberVaultX_Presentation.pptx' });
