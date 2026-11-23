-- ============================================
-- SCHEMAS
-- ============================================
create schema if not exists private;

-- ============================================
-- ENUMS
-- ============================================

-- ============================================
-- TABLES
-- ============================================

-- ============================================
-- GRANTS
-- ============================================
-- private schmea: policies need to call is_admin()
grant usage on schema private to authenticated;

-- ============================================
-- FUNCTIONS
-- ============================================


/***** Private Functions *****/

create function private.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    new.updated_at := now();
    return new;
end;
$$;
revoke execute on function private.set_updated_at() from public;


create function private.is_driver()
returns boolean
language sql stable
security definer set search_path = ''
as $$
    select exists (
        select 1 from public.profiles
        where id = (select auth.uid()) and role = 'driver'
    );
$$;
revoke execute on function private.is_driver() from public;
grant execute on function private.is_driver() to authenticated;


create function private.is_admin()
returns boolean
language sql stable
security definer set search_path = ''
as $$
    select exists (
        select 1 from public.profiles
        where id = (select auth.uid()) and role = 'admin'
    );
$$;
revoke execute on function private.is_admin() from public;
grant execute on function private.is_admin() to authenticated;


create function private.add_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, email, first_name, last_name, age_range, income_range)
  values (
    new.id,
    new.email,
    new.raw_user_meta_data ->> 'first_name',
    nullif(new.raw_user_meta_data ->> 'last_name', ''),
    (new.raw_user_meta_data ->> 'age_range')::public.age_range,
    (new.raw_user_meta_data ->> 'income_range')::public.income_range
  );
  return new;
end;
$$;
revoke execute on function private.add_user() from public;


/***** Public Functions *****/


-- ============================================
-- INDEXES
-- ============================================


-- ============================================
-- TRIGGERS
-- ============================================
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function private.add_user();


-- ============================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================