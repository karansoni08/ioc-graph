-- IOC Graph — Supabase schema.
--
-- Run this once in the Supabase SQL editor (Dashboard -> SQL Editor -> New query -> Run).
-- Idempotent: safe to re-run after an edit.
--
-- SECURITY MODEL, which is the most important thing in this file:
-- Row Level Security is enabled on every table and NO policies are created for the `anon` or
-- `authenticated` roles. With RLS on and no policy, those roles can read and write nothing, so
-- the public anon key is useless against this data even if it leaks. All access goes through the
-- SERVICE-ROLE key, which bypasses RLS and is used only server-side by Streamlit. That key must
-- never be sent to a browser, committed, or placed anywhere a client can read it.
--
-- There is no per-user authorization here on purpose: this is one shared workspace gated by a
-- shared password at the application layer (see auth.py). Per-user accounts are future work, and
-- when they arrive the policies belong here rather than in the app.

-- ---------------------------------------------------------------- workspace (the graph)

create table if not exists workspace (
  id          text primary key default 'main',
  graph       jsonb not null,
  version     int   not null,
  updated_at  timestamptz default now()
);

-- Backups of the graph before each save, newest kept, oldest pruned to 10.
create table if not exists workspace_backups (
  id          bigserial primary key,
  workspace_id text not null default 'main',
  graph       jsonb not null,
  version     int   not null,
  created_at  timestamptz default now()
);

create index if not exists workspace_backups_created_idx
  on workspace_backups (workspace_id, created_at desc);

-- ---------------------------------------------------------------- reports

create table if not exists reports (
  sha256          text primary key,
  filename        text,
  ingested_at     timestamptz default now(),
  ingested_by     text,
  mode            text,
  tokens          int,
  cost_usd        numeric,
  security_status text
);

-- ---------------------------------------------------------------- LLM result cache

create table if not exists llm_cache (
  key        text primary key,
  value      jsonb,
  created_at timestamptz default now()
);

-- ---------------------------------------------------------------- agent run traces

create table if not exists agent_runs (
  id         text primary key,
  sha256     text,
  data       jsonb,
  created_at timestamptz default now()
);

create index if not exists agent_runs_created_idx on agent_runs (created_at desc);

-- ---------------------------------------------------------------- daily usage

create table if not exists usage_daily (
  day        date primary key,
  reports    int     default 0,
  agent_runs int     default 0,
  spend_usd  numeric default 0
);

-- ================================================================ functions

-- Optimistic-concurrency save. Updates only when the caller's expected version matches what is
-- stored, so two simultaneous uploads cannot silently overwrite each other. Returns the new
-- version, or -1 on conflict so the caller can reload and re-merge.
create or replace function save_graph(p_graph jsonb, p_expected int)
returns int
language plpgsql
security definer
set search_path = public
as $$
declare
  v_current int;
  v_new     int;
  v_graph   jsonb;
begin
  select version, graph into v_current, v_graph
    from workspace where id = 'main' for update;

  if v_current is null then
    -- First save. Only valid when the caller also believes the version is 0.
    if p_expected <> 0 then
      return -1;
    end if;
    insert into workspace (id, graph, version, updated_at)
      values ('main', p_graph, 1, now());
    return 1;
  end if;

  if v_current <> p_expected then
    return -1;
  end if;

  -- Keep a backup of what we are about to replace, then prune to the newest 10.
  insert into workspace_backups (workspace_id, graph, version)
    values ('main', v_graph, v_current);

  delete from workspace_backups
   where id in (
     select id from workspace_backups
      where workspace_id = 'main'
      order by created_at desc
      offset 10
   );

  v_new := v_current + 1;
  update workspace
     set graph = p_graph, version = v_new, updated_at = now()
   where id = 'main';

  return v_new;
end;
$$;

-- Atomically check every daily limit and reserve the usage in one statement, under a row lock.
-- Doing this in the application would be a race: two uploads could both read "19 of 20 used" and
-- both proceed. Returns false if any limit would be exceeded, in which case nothing is charged.
create or replace function reserve_usage(
  p_day          date,
  p_kind         text,       -- 'report' or 'agent'
  p_est_cost     numeric,
  p_report_limit int,
  p_agent_limit  int,
  p_spend_limit  numeric
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_reports int;
  v_agents  int;
  v_spend   numeric;
begin
  insert into usage_daily (day) values (p_day)
    on conflict (day) do nothing;

  select reports, agent_runs, spend_usd
    into v_reports, v_agents, v_spend
    from usage_daily where day = p_day for update;

  if p_kind = 'report' and v_reports + 1 > p_report_limit then
    return false;
  end if;

  if p_kind = 'agent' then
    -- An agent run is also a report-processing event, so both ceilings apply.
    if v_agents + 1 > p_agent_limit then
      return false;
    end if;
  end if;

  if v_spend + p_est_cost > p_spend_limit then
    return false;
  end if;

  update usage_daily
     set reports    = reports + (case when p_kind = 'report' then 1 else 0 end),
         agent_runs = agent_runs + (case when p_kind = 'agent' then 1 else 0 end),
         spend_usd  = spend_usd + p_est_cost
   where day = p_day;

  return true;
end;
$$;

-- Adjust the reserved estimate to what was actually spent. Called after the request completes,
-- with the delta (actual - estimate), which is normally negative because the estimate is a worst
-- case. Clamped at zero so a bad delta cannot make the day's spend negative.
create or replace function settle_usage(p_day date, p_delta numeric)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update usage_daily
     set spend_usd = greatest(0, spend_usd + p_delta)
   where day = p_day;
end;
$$;

-- ================================================================ RLS

-- Enable RLS and create NO policies for anon/authenticated. See the header comment: this is what
-- makes the data reachable only by the service-role key used server-side.
alter table workspace          enable row level security;
alter table workspace_backups  enable row level security;
alter table reports            enable row level security;
alter table llm_cache          enable row level security;
alter table agent_runs         enable row level security;
alter table usage_daily        enable row level security;

-- Also deny the functions to the public roles, so they cannot be called with the anon key.
revoke all on function save_graph(jsonb, int) from anon, authenticated;
revoke all on function reserve_usage(date, text, numeric, int, int, numeric) from anon, authenticated;
revoke all on function settle_usage(date, numeric) from anon, authenticated;
