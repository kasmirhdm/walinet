-- WaliNet: keamanan tenant + pembuatan tenant otomatis saat user mendaftar.
-- Jalankan sekali di Supabase SQL Editor.

-- owner_id mengikat satu akun Auth dengan satu tenant.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_owner_id_unique
ON public.tenant(owner_id);

ALTER TABLE public.tenant ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "tenant_select_own" ON public.tenant;
DROP POLICY IF EXISTS "tenant_insert_own" ON public.tenant;
DROP POLICY IF EXISTS "tenant_update_own" ON public.tenant;

CREATE POLICY "tenant_select_own"
ON public.tenant FOR SELECT
TO authenticated
USING (owner_id = auth.uid());

CREATE POLICY "tenant_insert_own"
ON public.tenant FOR INSERT
TO authenticated
WITH CHECK (owner_id = auth.uid());

CREATE POLICY "tenant_update_own"
ON public.tenant FOR UPDATE
TO authenticated
USING (owner_id = auth.uid())
WITH CHECK (owner_id = auth.uid());

-- Tenant dibuat otomatis ketika akun Supabase Auth berhasil dibuat.
-- Nama usaha dikirim melalui raw_user_meta_data.company_name.
CREATE OR REPLACE FUNCTION public.handle_new_walinet_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.tenant (owner_id, nama, email, status)
  VALUES (
    NEW.id,
    COALESCE(NULLIF(NEW.raw_user_meta_data->>'company_name',''), 'WaliNet'),
    NEW.email,
    'aktif'
  )
  ON CONFLICT (owner_id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created_walinet ON auth.users;
CREATE TRIGGER on_auth_user_created_walinet
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.handle_new_walinet_user();
