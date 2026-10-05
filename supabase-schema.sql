-- Run after enabling anonymous sign-ins in Supabase Authentication settings.
-- Signed-in visitors may edit any shared recipe; only its owner may delete it.
alter table public.shared_recipes
  add column if not exists owner_id uuid references auth.users(id) on delete cascade;

alter table public.shared_recipes
  alter column owner_id set not null;

alter table public.shared_recipes enable row level security;

drop policy if exists "Anyone can read and edit shared recipes" on public.shared_recipes;
drop policy if exists "Authenticated users can read shared recipes" on public.shared_recipes;
drop policy if exists "Authenticated users can create owned recipes" on public.shared_recipes;
drop policy if exists "Authenticated users can edit shared recipes" on public.shared_recipes;
drop policy if exists "Owners can delete shared recipes" on public.shared_recipes;

create policy "Authenticated users can read shared recipes"
  on public.shared_recipes
  for select
  to authenticated
  using (true);

create policy "Authenticated users can create owned recipes"
  on public.shared_recipes
  for insert
  to authenticated
  with check (owner_id = (select auth.uid()));

create policy "Authenticated users can edit shared recipes"
  on public.shared_recipes
  for update
  to authenticated
  using (true)
  with check (true);

create policy "Owners can delete shared recipes"
  on public.shared_recipes
  for delete
  to authenticated
  using (owner_id = (select auth.uid()));

create or replace function public.prevent_shared_recipe_owner_change()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.owner_id is distinct from old.owner_id then
    raise exception 'Recipe ownership cannot be changed';
  end if;
  return new;
end;
$$;

drop trigger if exists shared_recipe_owner_immutable on public.shared_recipes;
create trigger shared_recipe_owner_immutable
  before update on public.shared_recipes
  for each row
  execute function public.prevent_shared_recipe_owner_change();

revoke all on public.shared_recipes from anon;
grant select, insert, update, delete on public.shared_recipes to authenticated;
