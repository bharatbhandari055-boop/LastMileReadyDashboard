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
  topic text not null default 'General', -- module/topic name set at upload time; content sharing a topic is grouped together and shares one assessment
  type text not null,
  title text,
  description text,
  url text,
  required_minutes numeric,
  created_at bigint not null
);
alter table content enable row level security;

-- One assessment per (persona, topic) pair, instead of one per persona.
-- A topic with no content at all still works under the "General" default,
-- which preserves the old "one assessment for the whole persona" behavior.
create table if not exists assessments (
  persona text not null,
  topic text not null default 'General',
  questions jsonb not null default '[]',
  primary key (persona, topic)
);
alter table assessments enable row level security;

create table if not exists submissions (
  persona text not null,
  topic text not null default 'General',
  uid text not null,
  answers jsonb not null default '{}',
  submitted_at bigint not null,
  primary key (persona, topic, uid)
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
-- MIGRATION — only needed if you already ran the version of this file
-- from before "topic" existed. Safe to run again; every step is
-- idempotent. Skip this whole block on a brand-new project — the
-- create table statements above already include topic.
-- =========================================================

alter table content add column if not exists topic text not null default 'General';

alter table assessments add column if not exists topic text not null default 'General';
do $$
begin
  if exists (
    select 1 from information_schema.table_constraints
    where table_name = 'assessments' and constraint_type = 'PRIMARY KEY'
  ) then
    execute (
      select 'alter table assessments drop constraint ' || constraint_name
      from information_schema.table_constraints
      where table_name = 'assessments' and constraint_type = 'PRIMARY KEY'
      limit 1
    );
  end if;
  alter table assessments add primary key (persona, topic);
exception when others then null;
end $$;

alter table submissions add column if not exists topic text not null default 'General';
alter table submissions drop column if exists id; -- old synthetic id, replaced by the (persona, topic, uid) key below
do $$
begin
  if exists (
    select 1 from information_schema.table_constraints
    where table_name = 'submissions' and constraint_type = 'PRIMARY KEY'
  ) then
    execute (
      select 'alter table submissions drop constraint ' || constraint_name
      from information_schema.table_constraints
      where table_name = 'submissions' and constraint_type = 'PRIMARY KEY'
      limit 1
    );
  end if;
  alter table submissions add primary key (persona, topic, uid);
exception when others then null;
end $$;
