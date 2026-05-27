-- Limyra Studio — Database Schema
-- Run: npm run db:migrate:local  (local)
-- Run: npm run db:migrate         (production)

PRAGMA foreign_keys = ON;

-- -----------------------------------------------
-- PROJECTS
-- -----------------------------------------------
CREATE TABLE IF NOT EXISTS projects (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  slug         TEXT    NOT NULL UNIQUE,
  number       TEXT    NOT NULL,
  title_tr     TEXT    NOT NULL,
  title_en     TEXT    NOT NULL DEFAULT '',
  subtitle_tr  TEXT    NOT NULL DEFAULT '',
  subtitle_en  TEXT    NOT NULL DEFAULT '',
  year         INTEGER NOT NULL,
  location_tr  TEXT    NOT NULL DEFAULT '',
  location_en  TEXT    NOT NULL DEFAULT '',
  tag          TEXT    NOT NULL,              -- Residential | Workspace | Cultural | Founding
  area_m2      INTEGER,
  status       TEXT    NOT NULL DEFAULT 'Completed',  -- Completed | In Progress
  description_tr TEXT  NOT NULL DEFAULT '',
  description_en TEXT  NOT NULL DEFAULT '',
  essay_tr     TEXT    NOT NULL DEFAULT '',
  essay_en     TEXT    NOT NULL DEFAULT '',
  cover_image  TEXT,                           -- R2 public URL
  sort_order   INTEGER NOT NULL DEFAULT 0,
  published    INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS project_images (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  url         TEXT    NOT NULL,
  caption_tr  TEXT    NOT NULL DEFAULT '',
  caption_en  TEXT    NOT NULL DEFAULT '',
  sort_order  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS project_materials (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name_tr     TEXT    NOT NULL,
  name_en     TEXT    NOT NULL DEFAULT '',
  subtitle_tr TEXT    NOT NULL DEFAULT '',
  subtitle_en TEXT    NOT NULL DEFAULT '',
  bg_gradient TEXT    NOT NULL DEFAULT '',
  note        TEXT    NOT NULL DEFAULT '',
  sort_order  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS project_credits (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  role_tr     TEXT    NOT NULL,
  role_en     TEXT    NOT NULL DEFAULT '',
  value       TEXT    NOT NULL,
  sort_order  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS project_key_facts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key_tr      TEXT    NOT NULL,
  key_en      TEXT    NOT NULL DEFAULT '',
  value_tr    TEXT    NOT NULL,
  value_en    TEXT    NOT NULL DEFAULT '',
  sort_order  INTEGER NOT NULL DEFAULT 0
);

-- -----------------------------------------------
-- JOURNAL
-- -----------------------------------------------
CREATE TABLE IF NOT EXISTS journal_posts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  slug         TEXT    NOT NULL UNIQUE,
  kind         TEXT    NOT NULL,   -- Essay | Field Note | Konuşma | Book
  title_tr     TEXT    NOT NULL,
  title_en     TEXT    NOT NULL DEFAULT '',
  excerpt_tr   TEXT    NOT NULL DEFAULT '',
  excerpt_en   TEXT    NOT NULL DEFAULT '',
  body_tr      TEXT    NOT NULL DEFAULT '',
  body_en      TEXT    NOT NULL DEFAULT '',
  author       TEXT    NOT NULL DEFAULT '',
  cover_image  TEXT,
  read_time    INTEGER NOT NULL DEFAULT 5,
  published_at TEXT    NOT NULL DEFAULT (datetime('now')),
  published    INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- -----------------------------------------------
-- TEAM
-- -----------------------------------------------
CREATE TABLE IF NOT EXISTS team_members (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT    NOT NULL,
  role_tr    TEXT    NOT NULL,
  role_en    TEXT    NOT NULL DEFAULT '',
  avatar     TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0
);

-- -----------------------------------------------
-- PRESS
-- -----------------------------------------------
CREATE TABLE IF NOT EXISTS press_mentions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  year         INTEGER NOT NULL,
  project_name TEXT    NOT NULL,
  source       TEXT    NOT NULL,
  note         TEXT    NOT NULL DEFAULT '',
  sort_order   INTEGER NOT NULL DEFAULT 0
);

-- -----------------------------------------------
-- CONTACTS (form submissions)
-- -----------------------------------------------
CREATE TABLE IF NOT EXISTS contacts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT    NOT NULL,
  email        TEXT    NOT NULL,
  phone        TEXT,
  company      TEXT,
  project_type TEXT,
  scope        TEXT,
  timeline     TEXT,
  location     TEXT,
  area         TEXT,
  message      TEXT,
  read         INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- -----------------------------------------------
-- SETTINGS (key-value store for site content)
-- -----------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- -----------------------------------------------
-- APPROACH PAGE CONTENT
-- -----------------------------------------------
CREATE TABLE IF NOT EXISTS approach_pillars (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  num         TEXT    NOT NULL DEFAULT '',
  label_tr    TEXT    NOT NULL DEFAULT '',
  label_en    TEXT    NOT NULL DEFAULT '',
  title_tr    TEXT    NOT NULL DEFAULT '',
  title_en    TEXT    NOT NULL DEFAULT '',
  lede_tr     TEXT    NOT NULL DEFAULT '',
  lede_en     TEXT    NOT NULL DEFAULT '',
  body_tr     TEXT    NOT NULL DEFAULT '',
  body_en     TEXT    NOT NULL DEFAULT '',
  rules_tr    TEXT    NOT NULL DEFAULT '[]',
  rules_en    TEXT    NOT NULL DEFAULT '[]',
  sort_order  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS approach_stages (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  num            TEXT    NOT NULL DEFAULT '',
  title_tr       TEXT    NOT NULL DEFAULT '',
  title_en       TEXT    NOT NULL DEFAULT '',
  duration       TEXT    NOT NULL DEFAULT '',
  description_tr TEXT    NOT NULL DEFAULT '',
  description_en TEXT    NOT NULL DEFAULT '',
  sort_order     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS approach_principles (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  yes_tr     TEXT    NOT NULL DEFAULT '',
  yes_en     TEXT    NOT NULL DEFAULT '',
  no_tr      TEXT    NOT NULL DEFAULT '',
  no_en      TEXT    NOT NULL DEFAULT '',
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS approach_materials (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name_tr     TEXT    NOT NULL DEFAULT '',
  name_en     TEXT    NOT NULL DEFAULT '',
  subtitle    TEXT    NOT NULL DEFAULT '',
  bg_gradient TEXT    NOT NULL DEFAULT '',
  caption     TEXT    NOT NULL DEFAULT '',
  sort_order  INTEGER NOT NULL DEFAULT 0
);

-- -----------------------------------------------
-- ADMIN USERS
-- -----------------------------------------------
CREATE TABLE IF NOT EXISTS admin_users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  name          TEXT    NOT NULL,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- -----------------------------------------------
-- DEFAULT SETTINGS
-- -----------------------------------------------
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('site_title_tr',       'Limyra Studio — Mimarlık & İç Mimarlık'),
  ('site_title_en',       'Limyra Studio — Architecture & Interiors'),
  ('meta_description_tr', 'Limyra Studio, sade ve dayanıklı mekânlar tasarlar. Az olanın, uzun yıllar sevildiğine inanırız.'),
  ('meta_description_en', 'Limyra Studio designs simple and enduring spaces. We believe in less that is loved for many years.'),
  ('hero_title_tr',       'Bir eşik, bir oran, bir ev.'),
  ('hero_title_en',       'A threshold, a proportion, a home.'),
  ('hero_lede_tr',        'Limyra Studio, sade ve dayanıklı mekânlar tasarlar. Az olanın, uzun yıllar sevildiğine inanırız.'),
  ('hero_lede_en',        'Limyra Studio designs simple and enduring spaces. We believe in less that is loved for many years.'),
  ('stats_built',         '24'),
  ('stats_in_progress',   '06'),
  ('stats_awards',        '09'),
  ('stats_projects',      '24'),
  ('newsletter_count',    '2.140'),
  ('contact_response_days', '7'),
  ('studio_address_tr',   'Asmalımescit Mah. 42 · Beyoğlu, İstanbul'),
  ('studio_address_en',   'Asmalımescit Mah. 42 · Beyoğlu, Istanbul'),
  ('studio_email',        'studio@limyra.studio'),
  ('studio_phone',        '+90 242 000 00 00'),
  ('studio_instagram',    '@limyrastudio'),
  ('approach_hero_lede_tr',    'Mimarlığı bir <em>cümle</em> gibi yazarız: konu, fiil, gereksiz olanın sessiz silinişi. Her proje üç sabit üzerine kurulur, beş aşamada okunur.'),
  ('approach_hero_lede_en',    'We write architecture like a <em>sentence</em>: subject, verb, the silent erasure of the unnecessary. Every project is built on three constants, read in five phases.'),
  ('approach_hero_body_tr',    'Limyra Studio konut, çalışma alanı ve küçük ölçekli kamusal yapılarla çalışır. Kavramsal araştırmadan inşaat denetimine kadar tüm aşamalarda müvekkilin yanındadır. Bu sayfa, çalışma biçimimizin <em>resmi olmayan</em> kullanım kılavuzudur.'),
  ('approach_hero_body_en',    'Limyra Studio works with residential, workspace and small-scale public buildings. It accompanies the client through every phase from conceptual research to construction supervision. This page is the <em>unofficial</em> manual for our working method.'),
  ('approach_manifesto_tr',    'Tasarım, sustuğunda en güçlü hâlindedir.'),
  ('approach_manifesto_en',    'Design is at its most powerful when it falls silent.'),
  ('approach_process_duration','Ortalama 16–22 ay'),
  ('approach_cta_title_tr',    'Bir söyleşi başlatalım.'),
  ('approach_cta_title_en',    'Let''s start a conversation.'),
  ('approach_cta_body_tr',     'Projenizden birkaç cümleyle bahsedin. Yedi iş günü içinde döner, ilk söyleşi randevusu öneririz.'),
  ('approach_cta_body_en',     'Tell us about your project in a few sentences. We will respond within seven working days and suggest a first meeting.');
