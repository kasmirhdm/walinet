-- WaliNet: keamanan tenant + role admin/tenant + pembuatan tenant otomatis.
-- Jalankan sekali di Supabase SQL Editor.

-- ============================================================
-- 1. ROLE USER
-- ============================================================
CREATE TABLE IF NOT EXISTS public.walinet_profile (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'tenant' CHECK (role IN ('admin','tenant')),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.walinet_profile ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "profile_select_own" ON public.walinet_profile;
CREATE POLICY "profile_select_own"
ON public.walinet_profile FOR SELECT
TO authenticated
USING (id = auth.uid());

-- Helper function untuk policy admin tanpa recursive RLS.
CREATE OR REPLACE FUNCTION public.is_walinet_admin()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.walinet_profile
    WHERE id = auth.uid() AND role = 'admin'
  );
$$;

REVOKE ALL ON FUNCTION public.is_walinet_admin() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_walinet_admin() TO authenticated;

-- ============================================================
-- 2. TENANT
-- ============================================================
CREATE UNIQUE INDEX IF NOT EXISTS tenant_owner_id_unique
ON public.tenant(owner_id);

ALTER TABLE public.tenant ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "tenant_select_own" ON public.tenant;
DROP POLICY IF EXISTS "tenant_insert_own" ON public.tenant;
DROP POLICY IF EXISTS "tenant_update_own" ON public.tenant;
DROP POLICY IF EXISTS "tenant_admin_all" ON public.tenant;

CREATE POLICY "tenant_select_own"
ON public.tenant FOR SELECT
TO authenticated
USING (owner_id = auth.uid());

CREATE POLICY "tenant_admin_all"
ON public.tenant FOR ALL
TO authenticated
USING (public.is_walinet_admin())
WITH CHECK (public.is_walinet_admin());

CREATE POLICY "tenant_insert_own"
ON public.tenant FOR INSERT
TO authenticated
WITH CHECK (owner_id = auth.uid());

CREATE POLICY "tenant_update_own"
ON public.tenant FOR UPDATE
TO authenticated
USING (owner_id = auth.uid())
WITH CHECK (owner_id = auth.uid());

-- ============================================================
-- 3. AUTO-PROFILE + AUTO-TENANT SAAT SIGNUP
-- ============================================================
CREATE OR REPLACE FUNCTION public.handle_new_walinet_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.walinet_profile (id, role)
  VALUES (NEW.id, 'tenant')
  ON CONFLICT (id) DO NOTHING;

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

-- ============================================================
-- 4. MENJADIKAN AKUN ANDA SEBAGAI ADMIN
-- ============================================================
-- Setelah akun admin sudah terdaftar, jalankan query ini sekali
-- dengan mengganti email dengan email akun admin Anda:
--
-- UPDATE public.walinet_profile
-- SET role = 'admin'
-- WHERE id = (SELECT id FROM auth.users WHERE email = 'EMAIL_ADMIN_ANDA');
--
-- Jangan memberikan role admin melalui frontend.
