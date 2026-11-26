-- ============================================
-- SCHEMAS
-- ============================================
create schema if not exists private;

-- ============================================
-- ENUMS
-- ============================================
create type user_role as enum (
    'rider',
    'driver',
    'admin'
);

create type age_range as enum (
    'under_18', 
    '18_24', 
    '25_34', 
    '35_44', 
    '45_54',
    '55_64',
    '65_plus', 
    'prefer_not_to_say'
);

create type income_range as enum (
    'under_15000', 
    '15000_24999', 
    '25000_34999', 
    '35000_49999', 
    '50000_74999', 
    '75000_99999', 
    '100000_plus', 
    'prefer_not_to_say'
);


-- ============================================
-- TABLES
-- ============================================
create table person (
    id not null uuid primary key references auth.users,
    role not null user_role DEFAULT rider,
    first_name not null text check (char_length(trim(first_name)) between 1 and 50),
    last_name text check (char_length(last_name) <= 50),
    full_name not null text GENERATED ALWAYS AS trim(first_name || ' ' || coalesce(last_name, '')) STORED
    display_name text NOT NULL check (TRIM(display_name)  ),
    email not null text,
    phone text check (phone ~ '^\+[1-9][0-9]{1,14}$'),
    age_range not null age_range,
    income_range not null income_range,
    notify_announcements not null boolean,
    created_at not null timestamptz,
    updated_at not null timestamptz
);

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