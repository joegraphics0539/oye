-- OYE THRIFT STORE - schema, security rules and image storage.
-- Safe to run more than once: it only creates what is missing and never drops data.
-- Run in: Supabase Dashboard > SQL Editor.

------------------------------------------------------------------------
-- 1. Administrators (the ONLY source of admin rights)
------------------------------------------------------------------------
create table if not exists public.admin_users (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.admin_users enable row level security;
-- No policies on purpose: nobody can read or write this table through the API.
-- Admin rights are only granted by running 002_make_owner_admin.sql in the SQL editor.

create or replace function public.is_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (select 1 from public.admin_users where user_id = auth.uid());
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

------------------------------------------------------------------------
-- 2. Products
------------------------------------------------------------------------
create sequence if not exists public.product_code_seq start 1;

create table if not exists public.products (
  id            uuid primary key default gen_random_uuid(),
  product_code  text not null unique,
  name          text not null,
  description   text not null default '',
  price         numeric(12,2) not null check (price >= 0),
  sale_price    numeric(12,2) check (sale_price is null or sale_price >= 0),
  category      text not null default '',
  collection    text not null default 'both' check (collection in ('mens','womens','both')),
  sizes         text[] not null default '{}',
  colours       text[] not null default '{}',
  in_stock      boolean not null default true,
  is_new        boolean not null default false,
  is_featured   boolean not null default false,
  alt_text      text not null default '',
  -- Array of storage paths (e.g. "products/<uuid>.jpg") in the product-images bucket.
  -- Older Sitedrop references ({fileId,bucket}) are tolerated until re-uploaded.
  images        jsonb not null default '[]'::jsonb,
  legacy_id     text unique,               -- id in the old Sitedrop store (import is repeatable)
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index if not exists products_created_idx on public.products (created_at desc);

-- Code generation: ALWAYS server-side, from a sequence that never goes backwards,
-- so a deleted product's code is never reused. Client-supplied codes are ignored.
create or replace function public.products_before_insert()
returns trigger language plpgsql security definer set search_path = public
as $$
declare n bigint;
begin
  n := nextval('public.product_code_seq');
  new.product_code := 'OYE-TS-' || case when n < 10000 then lpad(n::text, 4, '0') else n::text end;
  new.created_at := coalesce(new.created_at, now());
  new.updated_at := now();
  return new;
end $$;

-- Editing can never change the code, the id or the creation time.
create or replace function public.products_before_update()
returns trigger language plpgsql
as $$
begin
  new.id := old.id;
  new.product_code := old.product_code;
  new.created_at := old.created_at;
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists trg_products_before_insert on public.products;
create trigger trg_products_before_insert before insert on public.products
  for each row execute function public.products_before_insert();
drop trigger if exists trg_products_before_update on public.products;
create trigger trg_products_before_update before update on public.products
  for each row execute function public.products_before_update();

alter table public.products enable row level security;
revoke insert, update, delete on public.products from anon;

drop policy if exists "products are public to read" on public.products;
create policy "products are public to read" on public.products
  for select to anon, authenticated using (true);

drop policy if exists "admins insert products" on public.products;
create policy "admins insert products" on public.products
  for insert to authenticated with check (public.is_admin());

drop policy if exists "admins update products" on public.products;
create policy "admins update products" on public.products
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "admins delete products" on public.products;
create policy "admins delete products" on public.products
  for delete to authenticated using (public.is_admin());

------------------------------------------------------------------------
-- 3. Saved carts (one private row per signed-in customer)
------------------------------------------------------------------------
create table if not exists public.carts (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  items      jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);
alter table public.carts enable row level security;
revoke all on public.carts from anon;

drop policy if exists "customers manage their own cart" on public.carts;
create policy "customers manage their own cart" on public.carts
  for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

------------------------------------------------------------------------
-- 4. Permanent image storage
------------------------------------------------------------------------
-- Public bucket: the storefront uses permanent public URLs (no expiring links).
-- Only administrators may add, replace or remove files.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('product-images', 'product-images', true, 5242880,
        array['image/jpeg','image/png','image/webp','image/gif'])
on conflict (id) do update
  set public = excluded.public,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "admins upload product images" on storage.objects;
create policy "admins upload product images" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'product-images' and public.is_admin());

drop policy if exists "admins update product images" on storage.objects;
create policy "admins update product images" on storage.objects
  for update to authenticated
  using (bucket_id = 'product-images' and public.is_admin())
  with check (bucket_id = 'product-images' and public.is_admin());

drop policy if exists "admins delete product images" on storage.objects;
create policy "admins delete product images" on storage.objects
  for delete to authenticated
  using (bucket_id = 'product-images' and public.is_admin());
