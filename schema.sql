-- LastMile Ready Dashboard — Supabase schema
-- Run this once in Supabase: Project → SQL Editor → New query → paste → Run.
--
-- Row Level Security is enabled with NO policies on every table, so the
-- Postgres REST API (anon/public key) can't read or write anything.
-- Only the server can, using the service_role key (which bypasses RLS
-- entirely) — same security model as the Firestore rules from before:
-- the browser never talks to the database directly.

create extension if not exists pgcrypto;

create table if not exists registrations (
  uid text primary key,
  name text not null,
  phone text not null,
  email text not null,
  hub text not null,
  city text not null,
  role text not null,
  pin text not null,
  status text not null default 'pending',
  note text,
  category text not null default 'User', -- 'Hope on Wheels' (rider) or 'User' (staff)
  submitted_at bigint not null
);
alter table registrations enable row level security;

create table if not exists profiles (
  id text primary key,
  name text,
  phone text,
  email text,
  hub text,
  city text,
  pin text,
  roles text[] not null default '{}',
  status text not null default 'approved',
  category text not null default 'User', -- 'Hope on Wheels' (rider) or 'User' (staff)
  must_change_pin boolean not null default false,
  approved_at bigint,
  updated_at bigint
);
alter table profiles enable row level security;

create table if not exists admins (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  pass_hash text not null,
  created_at bigint not null
);
alter table admins enable row level security;

create table if not exists content (
  id uuid primary key default gen_random_uuid(),
  persona text not null,
  type text not null,
  title text,
  description text,
  url text,
  required_minutes numeric,
  created_at bigint not null
);
alter table content enable row level security;

create table if not exists assessments (
  persona text primary key,
  questions jsonb not null default '[]', -- each mcq question carries a "correct" field (must equal one of "options")
  pass_score numeric not null default 80 -- percentage of mcq questions that must be correct to pass
);
alter table assessments enable row level security;

create table if not exists submissions (
  id text primary key, -- slug(persona)+"_"+uid
  persona text not null,
  uid text not null,
  answers jsonb not null default '{}',
  score numeric,      -- % of mcq questions answered correctly on this attempt
  passed boolean,      -- score >= that persona's pass_score at time of submission
  submitted_at bigint not null
);
alter table submissions enable row level security;

create table if not exists progress (
  id text primary key, -- slug(persona)+"_"+uid
  persona text not null,
  uid text not null,
  completed jsonb not null default '{}',
  updated_at bigint not null
);
alter table progress enable row level security;

-- =========================================================
-- MIGRATION — run this block if you already have the old schema
-- deployed (safe to re-run: every clause is guarded).
-- =========================================================
alter table registrations add column if not exists category text not null default 'User';
alter table profiles add column if not exists category text not null default 'User';
alter table profiles add column if not exists must_change_pin boolean not null default false;
alter table assessments add column if not exists pass_score numeric not null default 80;
alter table submissions add column if not exists score numeric;
alter table submissions add column if not exists passed boolean;
