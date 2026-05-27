import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

// -----------------------------------------------
// CORS
// -----------------------------------------------
app.use('*', cors({
  origin: (origin, c) => {
    const allowed = c.env.FRONTEND_URL || 'http://localhost:3000';
    if (!origin || origin === allowed || origin.startsWith('http://localhost')) return origin;
    return null;
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// -----------------------------------------------
// CRYPTO HELPERS
// -----------------------------------------------
async function hashPassword(password) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hashArr = Array.from(new Uint8Array(bits));
  const saltArr = Array.from(salt);
  return saltArr.map(b => b.toString(16).padStart(2, '0')).join('') + ':' +
         hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hashArr = Array.from(new Uint8Array(bits));
  const newHash = hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
  return newHash === hashHex;
}

async function signJwt(payload, secret) {
  const enc = new TextEncoder();
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const body = btoa(JSON.stringify(payload)).replace(/=/g, '');
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${header}.${body}.${sigB64}`;
}

async function verifyJwt(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// -----------------------------------------------
// AUTH MIDDLEWARE
// -----------------------------------------------
async function requireAuth(c, next) {
  const auth = c.req.header('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return c.json({ error: 'Unauthorized' }, 401);
  const payload = await verifyJwt(token, c.env.JWT_SECRET);
  if (!payload) return c.json({ error: 'Invalid or expired token' }, 401);
  c.set('admin', payload);
  await next();
}

// -----------------------------------------------
// SETUP (one-time admin creation)
// -----------------------------------------------
app.post('/api/setup', async (c) => {
  const { setupKey, email, password, name } = await c.req.json();
  if (setupKey !== c.env.SETUP_KEY) return c.json({ error: 'Invalid setup key' }, 403);
  const existing = await c.env.DB.prepare('SELECT id FROM admin_users LIMIT 1').first();
  if (existing) return c.json({ error: 'Admin already exists' }, 409);
  const hash = await hashPassword(password);
  await c.env.DB.prepare('INSERT INTO admin_users (email, password_hash, name) VALUES (?, ?, ?)')
    .bind(email, hash, name || null).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// AUTH
// -----------------------------------------------
app.post('/api/auth/login', async (c) => {
  const { email, password } = await c.req.json();
  const user = await c.env.DB.prepare('SELECT * FROM admin_users WHERE email = ?').bind(email).first();
  if (!user) return c.json({ error: 'Invalid credentials' }, 401);
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return c.json({ error: 'Invalid credentials' }, 401);
  const token = await signJwt(
    { sub: user.id, email: user.email, name: user.name, exp: Math.floor(Date.now() / 1000) + 86400 * 7 },
    c.env.JWT_SECRET
  );
  return c.json({ token, name: user.name, email: user.email });
});

// -----------------------------------------------
// CLOUDINARY HELPERS
// -----------------------------------------------
async function cloudinarySign(params, apiSecret) {
  const str = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&') + apiSecret;
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-1', enc.encode(str));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function cloudinaryDelete(publicId, env) {
  const timestamp = Math.floor(Date.now() / 1000);
  const params = { public_id: publicId, timestamp };
  const signature = await cloudinarySign(params, env.CLOUDINARY_SECRET);
  const form = new FormData();
  form.append('public_id', publicId);
  form.append('api_key', env.CLOUDINARY_KEY);
  form.append('timestamp', String(timestamp));
  form.append('signature', signature);
  await fetch(`https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD}/image/destroy`, {
    method: 'POST', body: form,
  }).catch(() => {});
}

// -----------------------------------------------
// IMAGE UPLOAD (admin) — Cloudinary
// -----------------------------------------------
app.post('/api/admin/upload', requireAuth, async (c) => {
  const formData = await c.req.formData();
  const file = formData.get('file');
  if (!file || typeof file === 'string') return c.json({ error: 'No file' }, 400);

  const ext = (file.name || '').split('.').pop().toLowerCase();
  const allowed = ['jpg', 'jpeg', 'png', 'webp', 'avif'];
  if (!allowed.includes(ext)) return c.json({ error: 'Invalid file type' }, 400);

  const timestamp = Math.floor(Date.now() / 1000);
  const params = { folder: 'limyra', timestamp };
  const signature = await cloudinarySign(params, c.env.CLOUDINARY_SECRET);

  const upload = new FormData();
  upload.append('file', file);
  upload.append('api_key', c.env.CLOUDINARY_KEY);
  upload.append('timestamp', String(timestamp));
  upload.append('folder', 'limyra');
  upload.append('signature', signature);

  const res = await fetch(
    `https://api.cloudinary.com/v1_1/${c.env.CLOUDINARY_CLOUD}/image/upload`,
    { method: 'POST', body: upload }
  );
  if (!res.ok) return c.json({ error: 'Upload failed' }, 500);
  const data = await res.json();
  return c.json({ url: data.secure_url, key: data.public_id });
});

// -----------------------------------------------
// PUBLIC: SETTINGS
// -----------------------------------------------
app.get('/api/settings', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT key, value FROM settings').all();
  const out = {};
  for (const r of results) out[r.key] = r.value;
  return c.json(out);
});

// -----------------------------------------------
// PUBLIC: PROJECTS
// -----------------------------------------------
app.get('/api/projects', async (c) => {
  const tag = c.req.query('tag');
  const status = c.req.query('status');
  const archive = c.req.query('archive'); // "true" → only archived (no number 007+, just 001-006)

  let sql = 'SELECT * FROM projects WHERE published = 1';
  const binds = [];

  if (tag) { sql += ' AND tag = ?'; binds.push(tag); }
  if (status) { sql += ' AND status = ?'; binds.push(status); }

  sql += ' ORDER BY sort_order DESC';

  const { results } = await c.env.DB.prepare(sql).bind(...binds).all();
  return c.json(results);
});

app.get('/api/projects/:slug', async (c) => {
  const slug = c.req.param('slug');
  const project = await c.env.DB.prepare('SELECT * FROM projects WHERE slug = ? AND published = 1').bind(slug).first();
  if (!project) return c.json({ error: 'Not found' }, 404);

  const [images, materials, credits, keyFacts] = await Promise.all([
    c.env.DB.prepare('SELECT * FROM project_images WHERE project_id = ? ORDER BY sort_order').bind(project.id).all(),
    c.env.DB.prepare('SELECT * FROM project_materials WHERE project_id = ? ORDER BY sort_order').bind(project.id).all(),
    c.env.DB.prepare('SELECT * FROM project_credits WHERE project_id = ? ORDER BY sort_order').bind(project.id).all(),
    c.env.DB.prepare('SELECT * FROM project_key_facts WHERE project_id = ? ORDER BY sort_order').bind(project.id).all(),
  ]);

  return c.json({
    ...project,
    images: images.results,
    materials: materials.results,
    credits: credits.results,
    key_facts: keyFacts.results,
  });
});

// -----------------------------------------------
// PUBLIC: JOURNAL
// -----------------------------------------------
app.get('/api/journal', async (c) => {
  const kind = c.req.query('kind');
  let sql = 'SELECT id, slug, kind, title_tr, title_en, excerpt_tr, excerpt_en, author, cover_image, read_time, published_at FROM journal_posts WHERE published = 1';
  const binds = [];
  if (kind) { sql += ' AND kind = ?'; binds.push(kind); }
  sql += ' ORDER BY published_at DESC';
  const { results } = await c.env.DB.prepare(sql).bind(...binds).all();
  return c.json(results);
});

app.get('/api/journal/:slug', async (c) => {
  const slug = c.req.param('slug');
  const post = await c.env.DB.prepare('SELECT * FROM journal_posts WHERE slug = ? AND published = 1').bind(slug).first();
  if (!post) return c.json({ error: 'Not found' }, 404);
  return c.json(post);
});

// -----------------------------------------------
// PUBLIC: TEAM
// -----------------------------------------------
app.get('/api/team', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM team_members ORDER BY sort_order').all();
  return c.json(results);
});

// -----------------------------------------------
// PUBLIC: PRESS
// -----------------------------------------------
app.get('/api/press', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM press_mentions ORDER BY sort_order').all();
  return c.json(results);
});

// -----------------------------------------------
// PUBLIC: CONTACT FORM
// -----------------------------------------------
app.post('/api/contact', async (c) => {
  const body = await c.req.json();
  const { name, email, phone, company, project_type, scope, timeline, location, area, message } = body;

  if (!name || !email || !message) return c.json({ error: 'name, email, message required' }, 400);

  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRe.test(email)) return c.json({ error: 'Invalid email' }, 400);

  await c.env.DB.prepare(
    'INSERT INTO contacts (name, email, phone, company, project_type, scope, timeline, location, area, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(name, email, phone || null, company || null, project_type || null, scope || null, timeline || null, location || null, area || null, message).run();

  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: STATS
// -----------------------------------------------
app.get('/api/admin/stats', requireAuth, async (c) => {
  const [projects, journal, contacts, unread] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as n FROM projects').first(),
    c.env.DB.prepare('SELECT COUNT(*) as n FROM journal_posts').first(),
    c.env.DB.prepare('SELECT COUNT(*) as n FROM contacts').first(),
    c.env.DB.prepare('SELECT COUNT(*) as n FROM contacts WHERE read = 0').first(),
  ]);
  return c.json({ projects: projects.n, journal: journal.n, contacts: contacts.n, unread: unread.n });
});

// -----------------------------------------------
// ADMIN: PROJECTS CRUD
// -----------------------------------------------
app.get('/api/admin/projects', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM projects ORDER BY sort_order DESC').all();
  return c.json(results);
});

app.get('/api/admin/projects/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const project = await c.env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(id).first();
  if (!project) return c.json({ error: 'Not found' }, 404);
  const [images, materials, credits, keyFacts] = await Promise.all([
    c.env.DB.prepare('SELECT * FROM project_images WHERE project_id = ? ORDER BY sort_order').bind(id).all(),
    c.env.DB.prepare('SELECT * FROM project_materials WHERE project_id = ? ORDER BY sort_order').bind(id).all(),
    c.env.DB.prepare('SELECT * FROM project_credits WHERE project_id = ? ORDER BY sort_order').bind(id).all(),
    c.env.DB.prepare('SELECT * FROM project_key_facts WHERE project_id = ? ORDER BY sort_order').bind(id).all(),
  ]);
  return c.json({ ...project, images: images.results, materials: materials.results, credits: credits.results, key_facts: keyFacts.results });
});

app.post('/api/admin/projects', requireAuth, async (c) => {
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    `INSERT INTO projects (slug,number,title_tr,title_en,subtitle_tr,subtitle_en,year,location_tr,location_en,tag,area_m2,status,description_tr,description_en,essay_tr,essay_en,cover_image,sort_order,published)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
     RETURNING *`
  ).bind(b.slug,b.number,b.title_tr,b.title_en||'',b.subtitle_tr||'',b.subtitle_en||'',b.year,b.location_tr,b.location_en||'',b.tag,b.area_m2||null,b.status||'Completed',b.description_tr||'',b.description_en||'',b.essay_tr||'',b.essay_en||'',b.cover_image||null,b.sort_order||0,b.published??1).first();
  return c.json(r, 201);
});

app.put('/api/admin/projects/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    `UPDATE projects SET slug=?,number=?,title_tr=?,title_en=?,subtitle_tr=?,subtitle_en=?,year=?,location_tr=?,location_en=?,tag=?,area_m2=?,status=?,description_tr=?,description_en=?,essay_tr=?,essay_en=?,cover_image=?,sort_order=?,published=?,updated_at=datetime('now')
     WHERE id=? RETURNING *`
  ).bind(b.slug,b.number,b.title_tr,b.title_en||'',b.subtitle_tr||'',b.subtitle_en||'',b.year,b.location_tr,b.location_en||'',b.tag,b.area_m2||null,b.status,b.description_tr||'',b.description_en||'',b.essay_tr||'',b.essay_en||'',b.cover_image||null,b.sort_order||0,b.published??1,id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.delete('/api/admin/projects/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  await c.env.DB.prepare('DELETE FROM projects WHERE id = ?').bind(id).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: PROJECT IMAGES
// -----------------------------------------------
app.get('/api/admin/projects/:id/images', requireAuth, async (c) => {
  const id = c.req.param('id');
  const { results } = await c.env.DB.prepare('SELECT * FROM project_images WHERE project_id = ? ORDER BY sort_order').bind(id).all();
  return c.json(results);
});

app.post('/api/admin/projects/:id/images', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO project_images (project_id, url, caption_tr, caption_en, sort_order) VALUES (?,?,?,?,?) RETURNING *'
  ).bind(id, b.url, b.caption_tr||'', b.caption_en||'', b.sort_order||0).first();
  return c.json(r, 201);
});

app.put('/api/admin/images/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE project_images SET url=?, caption_tr=?, caption_en=?, sort_order=? WHERE id=? RETURNING *'
  ).bind(b.url, b.caption_tr||'', b.caption_en||'', b.sort_order||0, id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.delete('/api/admin/images/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const img = await c.env.DB.prepare('SELECT url FROM project_images WHERE id = ?').bind(id).first();
  if (img && img.url && c.env.CLOUDINARY_CLOUD) {
    // Extract public_id from Cloudinary URL (e.g. limyra/abc123)
    const match = img.url.match(/\/limyra\/([^/.]+)/);
    if (match) await cloudinaryDelete(`limyra/${match[1]}`, c.env);
  }
  await c.env.DB.prepare('DELETE FROM project_images WHERE id = ?').bind(id).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: PROJECT MATERIALS
// -----------------------------------------------
app.get('/api/admin/projects/:id/materials', requireAuth, async (c) => {
  const id = c.req.param('id');
  const { results } = await c.env.DB.prepare('SELECT * FROM project_materials WHERE project_id = ? ORDER BY sort_order').bind(id).all();
  return c.json(results);
});

app.post('/api/admin/projects/:id/materials', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO project_materials (project_id,name_tr,name_en,subtitle_tr,subtitle_en,bg_gradient,note,sort_order) VALUES (?,?,?,?,?,?,?,?) RETURNING *'
  ).bind(id, b.name_tr, b.name_en||'', b.subtitle_tr||'', b.subtitle_en||'', b.bg_gradient||'', b.note||'', b.sort_order||0).first();
  return c.json(r, 201);
});

app.put('/api/admin/materials/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE project_materials SET name_tr=?,name_en=?,subtitle_tr=?,subtitle_en=?,bg_gradient=?,note=?,sort_order=? WHERE id=? RETURNING *'
  ).bind(b.name_tr, b.name_en||'', b.subtitle_tr||'', b.subtitle_en||'', b.bg_gradient||'', b.note||'', b.sort_order||0, id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.delete('/api/admin/materials/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM project_materials WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: PROJECT CREDITS
// -----------------------------------------------
app.post('/api/admin/projects/:id/credits', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO project_credits (project_id,role_tr,role_en,value,sort_order) VALUES (?,?,?,?,?) RETURNING *'
  ).bind(id, b.role_tr, b.role_en||'', b.value, b.sort_order||0).first();
  return c.json(r, 201);
});

app.put('/api/admin/credits/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE project_credits SET role_tr=?,role_en=?,value=?,sort_order=? WHERE id=? RETURNING *'
  ).bind(b.role_tr, b.role_en||'', b.value, b.sort_order||0, id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.delete('/api/admin/credits/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM project_credits WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: PROJECT KEY FACTS
// -----------------------------------------------
app.post('/api/admin/projects/:id/key-facts', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO project_key_facts (project_id,key_tr,key_en,value_tr,value_en,sort_order) VALUES (?,?,?,?,?,?) RETURNING *'
  ).bind(id, b.key_tr, b.key_en||'', b.value_tr, b.value_en||'', b.sort_order||0).first();
  return c.json(r, 201);
});

app.put('/api/admin/key-facts/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE project_key_facts SET key_tr=?,key_en=?,value_tr=?,value_en=?,sort_order=? WHERE id=? RETURNING *'
  ).bind(b.key_tr, b.key_en||'', b.value_tr, b.value_en||'', b.sort_order||0, id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.delete('/api/admin/key-facts/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM project_key_facts WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: JOURNAL CRUD
// -----------------------------------------------
app.get('/api/admin/journal', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM journal_posts ORDER BY published_at DESC').all();
  return c.json(results);
});

app.post('/api/admin/journal', requireAuth, async (c) => {
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    `INSERT INTO journal_posts (slug,kind,title_tr,title_en,excerpt_tr,excerpt_en,body_tr,body_en,author,cover_image,read_time,published_at,published)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *`
  ).bind(b.slug,b.kind,b.title_tr,b.title_en||'',b.excerpt_tr||'',b.excerpt_en||'',b.body_tr||'',b.body_en||'',b.author||'',b.cover_image||null,b.read_time||5,b.published_at||new Date().toISOString(),b.published??1).first();
  return c.json(r, 201);
});

app.put('/api/admin/journal/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    `UPDATE journal_posts SET slug=?,kind=?,title_tr=?,title_en=?,excerpt_tr=?,excerpt_en=?,body_tr=?,body_en=?,author=?,cover_image=?,read_time=?,published_at=?,published=?,updated_at=datetime('now')
     WHERE id=? RETURNING *`
  ).bind(b.slug,b.kind,b.title_tr,b.title_en||'',b.excerpt_tr||'',b.excerpt_en||'',b.body_tr||'',b.body_en||'',b.author||'',b.cover_image||null,b.read_time||5,b.published_at,b.published??1,id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.delete('/api/admin/journal/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM journal_posts WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: TEAM CRUD
// -----------------------------------------------
app.get('/api/admin/team', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM team_members ORDER BY sort_order').all();
  return c.json(results);
});

app.post('/api/admin/team', requireAuth, async (c) => {
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO team_members (name,role_tr,role_en,avatar,sort_order) VALUES (?,?,?,?,?) RETURNING *'
  ).bind(b.name, b.role_tr, b.role_en||'', b.avatar||null, b.sort_order||0).first();
  return c.json(r, 201);
});

app.put('/api/admin/team/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE team_members SET name=?,role_tr=?,role_en=?,avatar=?,sort_order=? WHERE id=? RETURNING *'
  ).bind(b.name, b.role_tr, b.role_en||'', b.avatar||null, b.sort_order||0, id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.delete('/api/admin/team/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM team_members WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: PRESS CRUD
// -----------------------------------------------
app.get('/api/admin/press', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM press_mentions ORDER BY sort_order').all();
  return c.json(results);
});

app.post('/api/admin/press', requireAuth, async (c) => {
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO press_mentions (year,project_name,source,note,sort_order) VALUES (?,?,?,?,?) RETURNING *'
  ).bind(b.year, b.project_name, b.source, b.note||'', b.sort_order||0).first();
  return c.json(r, 201);
});

app.put('/api/admin/press/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE press_mentions SET year=?,project_name=?,source=?,note=?,sort_order=? WHERE id=? RETURNING *'
  ).bind(b.year, b.project_name, b.source, b.note||'', b.sort_order||0, id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.delete('/api/admin/press/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM press_mentions WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: CONTACTS
// -----------------------------------------------
app.get('/api/admin/contacts', requireAuth, async (c) => {
  const read = c.req.query('read');
  let sql = 'SELECT * FROM contacts';
  const binds = [];
  if (read === '0') { sql += ' WHERE read = 0'; }
  sql += ' ORDER BY created_at DESC';
  const { results } = await c.env.DB.prepare(sql).bind(...binds).all();
  return c.json(results);
});

app.put('/api/admin/contacts/:id/read', requireAuth, async (c) => {
  await c.env.DB.prepare('UPDATE contacts SET read = 1 WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

app.delete('/api/admin/contacts/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM contacts WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// ADMIN: SETTINGS
// -----------------------------------------------
app.get('/api/admin/settings', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT key, value FROM settings').all();
  const out = {};
  for (const r of results) out[r.key] = r.value;
  return c.json(out);
});

app.put('/api/admin/settings', requireAuth, async (c) => {
  const b = await c.req.json();
  const stmts = Object.entries(b).map(([key, value]) =>
    c.env.DB.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')")
      .bind(key, value)
  );
  await c.env.DB.batch(stmts);
  return c.json({ ok: true });
});

// -----------------------------------------------
// PUBLIC: APPROACH
// -----------------------------------------------
app.get('/api/approach', async (c) => {
  const [settingsRes, pillarsRes, stagesRes, principlesRes, materialsRes] = await Promise.all([
    c.env.DB.prepare("SELECT key, value FROM settings WHERE key LIKE 'approach_%'").all(),
    c.env.DB.prepare('SELECT * FROM approach_pillars ORDER BY sort_order').all(),
    c.env.DB.prepare('SELECT * FROM approach_stages ORDER BY sort_order').all(),
    c.env.DB.prepare('SELECT * FROM approach_principles ORDER BY sort_order').all(),
    c.env.DB.prepare('SELECT * FROM approach_materials ORDER BY sort_order').all(),
  ]);
  const settings = {};
  for (const r of settingsRes.results) settings[r.key] = r.value;
  return c.json({
    settings,
    pillars: pillarsRes.results,
    stages: stagesRes.results,
    principles: principlesRes.results,
    materials: materialsRes.results,
  });
});

// -----------------------------------------------
// ADMIN: APPROACH (read all)
// -----------------------------------------------
app.get('/api/admin/approach', requireAuth, async (c) => {
  const [settingsRes, pillarsRes, stagesRes, principlesRes, materialsRes] = await Promise.all([
    c.env.DB.prepare("SELECT key, value FROM settings WHERE key LIKE 'approach_%'").all(),
    c.env.DB.prepare('SELECT * FROM approach_pillars ORDER BY sort_order').all(),
    c.env.DB.prepare('SELECT * FROM approach_stages ORDER BY sort_order').all(),
    c.env.DB.prepare('SELECT * FROM approach_principles ORDER BY sort_order').all(),
    c.env.DB.prepare('SELECT * FROM approach_materials ORDER BY sort_order').all(),
  ]);
  const settings = {};
  for (const r of settingsRes.results) settings[r.key] = r.value;
  return c.json({
    settings,
    pillars: pillarsRes.results,
    stages: stagesRes.results,
    principles: principlesRes.results,
    materials: materialsRes.results,
  });
});

// ADMIN: APPROACH PILLARS
app.put('/api/admin/approach/pillars/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE approach_pillars SET num=?,label_tr=?,label_en=?,title_tr=?,title_en=?,lede_tr=?,lede_en=?,body_tr=?,body_en=?,rules_tr=?,rules_en=?,sort_order=? WHERE id=? RETURNING *'
  ).bind(b.num||'',b.label_tr||'',b.label_en||'',b.title_tr||'',b.title_en||'',b.lede_tr||'',b.lede_en||'',b.body_tr||'',b.body_en||'',b.rules_tr||'[]',b.rules_en||'[]',b.sort_order||0,id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.post('/api/admin/approach/pillars', requireAuth, async (c) => {
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO approach_pillars (num,label_tr,label_en,title_tr,title_en,lede_tr,lede_en,body_tr,body_en,rules_tr,rules_en,sort_order) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *'
  ).bind(b.num||'',b.label_tr||'',b.label_en||'',b.title_tr||'',b.title_en||'',b.lede_tr||'',b.lede_en||'',b.body_tr||'',b.body_en||'',b.rules_tr||'[]',b.rules_en||'[]',b.sort_order||0).first();
  return c.json(r, 201);
});

app.delete('/api/admin/approach/pillars/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM approach_pillars WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// ADMIN: APPROACH STAGES
app.put('/api/admin/approach/stages/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE approach_stages SET num=?,title_tr=?,title_en=?,duration=?,description_tr=?,description_en=?,sort_order=? WHERE id=? RETURNING *'
  ).bind(b.num||'',b.title_tr||'',b.title_en||'',b.duration||'',b.description_tr||'',b.description_en||'',b.sort_order||0,id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.post('/api/admin/approach/stages', requireAuth, async (c) => {
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO approach_stages (num,title_tr,title_en,duration,description_tr,description_en,sort_order) VALUES (?,?,?,?,?,?,?) RETURNING *'
  ).bind(b.num||'',b.title_tr||'',b.title_en||'',b.duration||'',b.description_tr||'',b.description_en||'',b.sort_order||0).first();
  return c.json(r, 201);
});

app.delete('/api/admin/approach/stages/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM approach_stages WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// ADMIN: APPROACH PRINCIPLES
app.put('/api/admin/approach/principles/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE approach_principles SET yes_tr=?,yes_en=?,no_tr=?,no_en=?,sort_order=? WHERE id=? RETURNING *'
  ).bind(b.yes_tr||'',b.yes_en||'',b.no_tr||'',b.no_en||'',b.sort_order||0,id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.post('/api/admin/approach/principles', requireAuth, async (c) => {
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO approach_principles (yes_tr,yes_en,no_tr,no_en,sort_order) VALUES (?,?,?,?,?) RETURNING *'
  ).bind(b.yes_tr||'',b.yes_en||'',b.no_tr||'',b.no_en||'',b.sort_order||0).first();
  return c.json(r, 201);
});

app.delete('/api/admin/approach/principles/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM approach_principles WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// ADMIN: APPROACH MATERIALS
app.put('/api/admin/approach/materials/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'UPDATE approach_materials SET name_tr=?,name_en=?,subtitle=?,bg_gradient=?,caption=?,sort_order=? WHERE id=? RETURNING *'
  ).bind(b.name_tr||'',b.name_en||'',b.subtitle||'',b.bg_gradient||'',b.caption||'',b.sort_order||0,id).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  return c.json(r);
});

app.post('/api/admin/approach/materials', requireAuth, async (c) => {
  const b = await c.req.json();
  const r = await c.env.DB.prepare(
    'INSERT INTO approach_materials (name_tr,name_en,subtitle,bg_gradient,caption,sort_order) VALUES (?,?,?,?,?,?) RETURNING *'
  ).bind(b.name_tr||'',b.name_en||'',b.subtitle||'',b.bg_gradient||'',b.caption||'',b.sort_order||0).first();
  return c.json(r, 201);
});

app.delete('/api/admin/approach/materials/:id', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM approach_materials WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// -----------------------------------------------
// HEALTH CHECK
// -----------------------------------------------
app.get('/api/health', (c) => c.json({ ok: true, ts: new Date().toISOString() }));

export default app;
