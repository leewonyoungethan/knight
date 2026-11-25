-- 별빛 기사 순위표 (Supabase → SQL Editor에 통째로 붙여 넣고 Run)
-- 누구나 순위를 읽을 수 있고, 기록은 아래 두 함수로만 올리거나 이름을 바꿀 수 있어요.
-- 각 기기는 자기만 아는 비밀값(secret)을 가지고 있어서 남의 기록은 고칠 수 없어요.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.knight_scores (
  id          uuid primary key,
  secret_hash text not null,
  name        text not null check (char_length(name) between 1 and 12),
  cleared     int  not null check (cleared between 0 and 40),
  time_sec    int  not null check (time_sec between 0 and 3600000),
  kills       int  not null default 0 check (kills between 0 and 1000000),
  score       bigint not null,
  updated_at  timestamptz not null default now()
);

alter table public.knight_scores enable row level security;

drop policy if exists "anyone can read scores" on public.knight_scores;
create policy "anyone can read scores" on public.knight_scores for select using (true);

-- 표에 직접 쓰기는 막고, 읽을 때도 비밀값 칸은 안 보이게 해요.
revoke all on public.knight_scores from anon, authenticated;
grant select (id, name, cleared, time_sec, kills, score, updated_at) on public.knight_scores to anon, authenticated;

-- 기록 올리기: 처음이면 새로 만들고, 이미 있으면 비밀값이 맞고 점수가 더 좋을 때만 바꿔요.
create or replace function public.submit_knight_score(
  p_id uuid, p_secret text, p_name text, p_cleared int, p_time int, p_kills int)
returns void
language plpgsql security definer
set search_path = public, extensions
as $$
declare
  h text;
  s bigint;
  n text := left(regexp_replace(coalesce(p_name, ''), '[[:cntrl:]]', '', 'g'), 12);
begin
  if p_secret is null or char_length(p_secret) < 16 then raise exception 'bad secret'; end if;
  if n = '' then n := '기사'; end if;
  h := encode(digest(p_secret, 'sha256'), 'hex');
  s := p_cleared::bigint * 100000 + greatest(0, 99999 - p_time);
  insert into public.knight_scores (id, secret_hash, name, cleared, time_sec, kills, score)
  values (p_id, h, n, p_cleared, p_time, p_kills, s)
  on conflict (id) do update
    set name = excluded.name, cleared = excluded.cleared, time_sec = excluded.time_sec,
        kills = excluded.kills, score = excluded.score, updated_at = now()
    where public.knight_scores.secret_hash = h and excluded.score > public.knight_scores.score;
end $$;

-- 이름 바꾸기: 비밀값이 맞을 때만
create or replace function public.rename_knight_score(p_id uuid, p_secret text, p_name text)
returns void
language plpgsql security definer
set search_path = public, extensions
as $$
declare n text := left(regexp_replace(coalesce(p_name, ''), '[[:cntrl:]]', '', 'g'), 12);
begin
  if n = '' then return; end if;
  update public.knight_scores set name = n, updated_at = now()
   where id = p_id and secret_hash = encode(digest(p_secret, 'sha256'), 'hex');
end $$;

revoke all on function public.submit_knight_score(uuid, text, text, int, int, int) from public;
revoke all on function public.rename_knight_score(uuid, text, text) from public;
grant execute on function public.submit_knight_score(uuid, text, text, int, int, int) to anon, authenticated;
grant execute on function public.rename_knight_score(uuid, text, text) to anon, authenticated;
