-- Grants administrator rights to the store owner. Run ONCE, in the SQL editor, AFTER:
--   1. the owner has created an account on the website, and
--   2. the owner has clicked the confirmation link in the email Supabase sent.
-- Requiring a confirmed email means nobody can obtain admin by registering the owner's
-- address first. Registering never grants admin by itself - only this script does.
-- To add another administrator later, change the email below and run it again.

insert into public.admin_users (user_id)
select id
from auth.users
where lower(email) = lower('yetqueen11@gmail.com')
  and email_confirmed_at is not null
on conflict (user_id) do nothing;

-- Should list the owner. If it is empty, the account does not exist yet or is not confirmed.
select u.email, a.created_at as admin_since
from public.admin_users a join auth.users u on u.id = a.user_id;
