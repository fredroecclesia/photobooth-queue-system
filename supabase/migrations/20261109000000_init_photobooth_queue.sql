-- ============================================================================
-- PHOTOBOOTH QUEUE MANAGEMENT SYSTEM (v1.1 - Hardened & QA Verified)
-- Supabase PostgreSQL Schema, Constraints, RLS, Realtime Broadcast & Atomic RPCs
-- Berdasarkan PRD Tanggal 9 November 2026 & Hasil Audit QA/Security
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. TABLES & CONSTRAINTS (PRD Bab 12)
-- ============================================================================

-- 1.0 Table: admin_users (Whitelisted Admins - Mencegah Privilege Escalation)
CREATE TABLE IF NOT EXISTS public.admin_users (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fungsi Helper Otorisasi Admin (SECURITY DEFINER + SET search_path = public)
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.admin_users WHERE user_id = auth.uid()
    );
$$;

-- 12.3 Table: queue_settings (Dijamin tepat 1 baris dengan singleton_key)
CREATE TABLE IF NOT EXISTS public.queue_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    singleton_key BOOLEAN NOT NULL DEFAULT TRUE UNIQUE CHECK (singleton_key = TRUE),
    photobooth_name VARCHAR(100) NOT NULL DEFAULT 'SnapStudio Photobooth',
    logo_url TEXT DEFAULT '',
    queue_prefix VARCHAR(10) NOT NULL DEFAULT 'A',
    starting_number INTEGER NOT NULL DEFAULT 1 CHECK (starting_number >= 1),
    queue_limit INTEGER NOT NULL DEFAULT 100 CHECK (queue_limit >= 1),
    session_duration INTEGER NOT NULL DEFAULT 5 CHECK (session_duration >= 1),
    operational_status BOOLEAN NOT NULL DEFAULT TRUE,
    timezone VARCHAR(50) NOT NULL DEFAULT 'Asia/Jakarta',
    -- FR-064 & FR-065: Pengaturan Notifikasi & Audio Lengkap
    notification_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    near_turn_threshold INTEGER NOT NULL DEFAULT 3 CHECK (near_turn_threshold >= 1 AND near_turn_threshold <= 20),
    audio_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    speech_voice VARCHAR(100) DEFAULT 'id-ID',
    speech_rate NUMERIC(3,2) NOT NULL DEFAULT 1.00 CHECK (speech_rate >= 0.5 AND speech_rate <= 2.0),
    speech_volume NUMERIC(3,2) NOT NULL DEFAULT 1.00 CHECK (speech_volume >= 0.0 AND speech_volume <= 1.0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fungsi Helper Tanggal Lokal (WIB/WITA/WIT sesuai queue_settings.timezone)
CREATE OR REPLACE FUNCTION public.local_session_date()
RETURNS DATE
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
DECLARE
    v_tz VARCHAR(50);
BEGIN
    SELECT COALESCE(timezone, 'Asia/Jakarta') INTO v_tz FROM public.queue_settings WHERE singleton_key = TRUE LIMIT 1;
    RETURN (NOW() AT TIME ZONE COALESCE(v_tz, 'Asia/Jakarta'))::DATE;
END;
$$;

-- 12.2 Table: queue_sessions
CREATE TABLE IF NOT EXISTS public.queue_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_date DATE NOT NULL DEFAULT public.local_session_date(),
    status VARCHAR(20) NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Closed')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Pastikan hanya ada maksimal 1 sesi yang berstatus 'Active' pada satu waktu
CREATE UNIQUE INDEX IF NOT EXISTS idx_single_active_session
    ON public.queue_sessions ((1))
    WHERE status = 'Active';

-- 12.1 Table: queues
-- Catatan: tracking_token sudah UNIQUE sehingga otomatis memiliki B-Tree index unik
CREATE TABLE IF NOT EXISTS public.queues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES public.queue_sessions(id) ON DELETE RESTRICT,
    sequence_number INTEGER NOT NULL,
    ticket_number VARCHAR(20) NOT NULL,
    visitor_name VARCHAR(120) NOT NULL CHECK (
        char_length(trim(visitor_name)) BETWEEN 1 AND 120
        AND visitor_name !~ '[<>]'
    ),
    tracking_token UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'Waiting'
        CHECK (status IN ('Waiting', 'Called', 'Completed', 'Skipped', 'Cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    called_at TIMESTAMPTZ,
    recalled_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT uq_session_ticket_number UNIQUE (session_id, ticket_number),
    CONSTRAINT uq_session_sequence_number UNIQUE (session_id, sequence_number)
);

-- PRD Bab 5.3 & 12.5: Partial Unique Index untuk menjamin HANYA ADA SATU antrean
-- berstatus 'Called' dalam satu sesi pada level database.
CREATE UNIQUE INDEX IF NOT EXISTS idx_single_called_per_session
    ON public.queues (session_id)
    WHERE status = 'Called';

CREATE INDEX IF NOT EXISTS idx_queues_session_status_seq
    ON public.queues (session_id, status, sequence_number);

-- 12.4 Table: queue_history (Jejak Audit Permanen - ON DELETE SET NULL agar log tidak pernah hilang)
CREATE TABLE IF NOT EXISTS public.queue_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue_id UUID REFERENCES public.queues(id) ON DELETE SET NULL,
    session_id UUID REFERENCES public.queue_sessions(id) ON DELETE SET NULL,
    ticket_number VARCHAR(20) NOT NULL,
    old_status VARCHAR(20),
    new_status VARCHAR(20) NOT NULL,
    changed_by UUID,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_queue_history_queue_id
    ON public.queue_history (queue_id, changed_at DESC);

CREATE INDEX IF NOT EXISTS idx_queue_history_changed_at
    ON public.queue_history (changed_at DESC);

-- 12.5 Table: push_subscriptions (Dilengkapi flag deduplikasi notifikasi)
CREATE TABLE IF NOT EXISTS public.push_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue_id UUID NOT NULL REFERENCES public.queues(id) ON DELETE CASCADE,
    subscription JSONB NOT NULL,
    notified_near_turn BOOLEAN NOT NULL DEFAULT FALSE,
    notified_called BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_queue_subscription UNIQUE (queue_id)
);

-- 12.6 Table: public_queue_sync (Tabel Sinkronisasi Realtime Publik Tanpa Nama Pengunjung)
-- Mengatasi pembatasan RLS Realtime pada tabel queues tanpa pernah mengekspos visitor_name!
CREATE TABLE IF NOT EXISTS public.public_queue_sync (
    singleton_key BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton_key = TRUE),
    session_id UUID,
    currently_called VARCHAR(20),
    waiting_count INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 12.7 Table: queue_rate_limits (Pencegahan Spam / Bot pada take_queue)
CREATE TABLE IF NOT EXISTS public.queue_rate_limits (
    client_key VARCHAR(128) PRIMARY KEY,
    session_id UUID NOT NULL,
    last_taken_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ticket_count INTEGER NOT NULL DEFAULT 1
);

-- ============================================================================
-- 2. SEED INITIAL SETTINGS, SESSION & PUBLIC SYNC
-- ============================================================================

INSERT INTO public.queue_settings (
    singleton_key, photobooth_name, logo_url, queue_prefix, starting_number,
    queue_limit, session_duration, operational_status, timezone
)
VALUES (TRUE, 'SnapStudio Photobooth', '', 'A', 1, 100, 5, TRUE, 'Asia/Jakarta')
ON CONFLICT (singleton_key) DO NOTHING;

INSERT INTO public.queue_sessions (session_date, status)
SELECT public.local_session_date(), 'Active'
WHERE NOT EXISTS (SELECT 1 FROM public.queue_sessions WHERE status = 'Active');

INSERT INTO public.public_queue_sync (singleton_key, waiting_count, updated_at)
VALUES (TRUE, 0, NOW())
ON CONFLICT (singleton_key) DO NOTHING;

-- ============================================================================
-- 3. SEPARATED TRIGGERS:
--    3A. BEFORE UPDATE -> Validasi State Transition & Timestamp (Tanpa FK Error)
--    3B. AFTER INSERT OR UPDATE -> Audit Log ke queue_history & Update Realtime Sync
-- ============================================================================

CREATE OR REPLACE FUNCTION public.fn_validate_queue_status_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.status IS DISTINCT FROM NEW.status THEN
        -- Validasi State Transition sesuai PRD Bab 11.2:
        -- Waiting -> Called | Cancelled
        -- Called  -> Completed | Skipped
        -- Skipped -> Called
        IF NOT (
            (OLD.status = 'Waiting' AND NEW.status IN ('Called', 'Cancelled')) OR
            (OLD.status = 'Called'  AND NEW.status IN ('Completed', 'Skipped')) OR
            (OLD.status = 'Skipped' AND NEW.status = 'Called')
        ) THEN
            RAISE EXCEPTION 'Transisi status tidak valid dari % ke % (PRD 11.2)', OLD.status, NEW.status;
        END IF;

        -- Jangan menimpa called_at saat Recall agar rata-rata waktu tunggu (called_at - created_at) tidak bias!
        IF NEW.status = 'Called' THEN
            IF OLD.called_at IS NULL THEN
                NEW.called_at := NOW();
            ELSE
                NEW.called_at := OLD.called_at;
                NEW.recalled_at := NOW();
            END IF;
        ELSIF NEW.status = 'Completed' THEN
            NEW.completed_at := NOW();
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_queue_status_audit ON public.queues;
DROP TRIGGER IF EXISTS trg_queue_before_update_guard ON public.queues;
CREATE TRIGGER trg_queue_before_update_guard
    BEFORE UPDATE ON public.queues
    FOR EACH ROW
    EXECUTE FUNCTION public.fn_validate_queue_status_transition();

-- Trigger AFTER INSERT OR UPDATE: Baris di `queues` sudah ada sehingga FK ke `queue_history` 100% aman!
CREATE OR REPLACE FUNCTION public.fn_after_queue_change_audit_and_sync()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_called VARCHAR(20);
    v_waiting INTEGER;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.queue_history (
            queue_id, session_id, ticket_number, old_status, new_status, changed_by, changed_at
        ) VALUES (
            NEW.id, NEW.session_id, NEW.ticket_number, NULL, NEW.status, auth.uid(), NOW()
        );
    ELSIF TG_OP = 'UPDATE' AND OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO public.queue_history (
            queue_id, session_id, ticket_number, old_status, new_status, changed_by, changed_at
        ) VALUES (
            NEW.id, NEW.session_id, NEW.ticket_number, OLD.status, NEW.status, auth.uid(), NOW()
        );
    END IF;

    -- Perbarui tabel public_queue_sync (tanpa nama pengunjung) agar Realtime sampai ke halaman publik!
    SELECT ticket_number INTO v_called
    FROM public.queues
    WHERE session_id = NEW.session_id AND status = 'Called'
    LIMIT 1;

    SELECT COUNT(*) INTO v_waiting
    FROM public.queues
    WHERE session_id = NEW.session_id AND status = 'Waiting';

    INSERT INTO public.public_queue_sync (singleton_key, session_id, currently_called, waiting_count, updated_at)
    VALUES (TRUE, NEW.session_id, v_called, v_waiting, NOW())
    ON CONFLICT (singleton_key) DO UPDATE
    SET session_id = EXCLUDED.session_id,
        currently_called = EXCLUDED.currently_called,
        waiting_count = EXCLUDED.waiting_count,
        updated_at = NOW();

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_queue_after_change_audit ON public.queues;
CREATE TRIGGER trg_queue_after_change_audit
    AFTER INSERT OR UPDATE ON public.queues
    FOR EACH ROW
    EXECUTE FUNCTION public.fn_after_queue_change_audit_and_sync();

-- ============================================================================
-- 4. ATOMIC RPC FUNCTIONS (Concurrency Safe, Rate-Limited & Admin Verified)
-- ============================================================================

-- 4.1 RPC: take_queue (Pengunjung Publik - Dilengkapi Sanitasi XSS, Rate Limit & Rumus Estimasi Konsisten)
CREATE OR REPLACE FUNCTION public.take_queue(
    p_visitor_name VARCHAR,
    p_client_fingerprint VARCHAR DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_clean_name VARCHAR(120);
    v_settings public.queue_settings%ROWTYPE;
    v_session public.queue_sessions%ROWTYPE;
    v_client_key VARCHAR(128);
    v_rate public.queue_rate_limits%ROWTYPE;
    v_total_count INTEGER;
    v_waiting_ahead INTEGER;
    v_has_called INTEGER;
    v_next_seq INTEGER;
    v_ticket_number VARCHAR(20);
    v_new_queue public.queues%ROWTYPE;
BEGIN
    -- Sanitasi karakter HTML untuk mencegah Stored XSS sejak level input
    v_clean_name := regexp_replace(trim(COALESCE(p_visitor_name, '')), '[<>]', '', 'g');
    IF char_length(v_clean_name) < 2 OR char_length(v_clean_name) > 100 THEN
        RAISE EXCEPTION 'Nama pengunjung wajib diisi (2–100 karakter tanpa simbol tag HTML).';
    END IF;

    -- Lock baris tunggal settings
    SELECT * INTO v_settings
    FROM public.queue_settings
    WHERE singleton_key = TRUE
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Konfigurasi sistem belum diatur.';
    END IF;

    IF NOT v_settings.operational_status THEN
        RAISE EXCEPTION 'Maaf, pendaftaran antrean photobooth sedang ditutup.';
    END IF;

    -- Ambil atau buat sesi aktif dengan tanggal zona waktu lokal (WIB/WITA)
    SELECT * INTO v_session
    FROM public.queue_sessions
    WHERE status = 'Active'
    LIMIT 1
    FOR UPDATE;

    IF NOT FOUND THEN
        INSERT INTO public.queue_sessions (session_date, status)
        VALUES (public.local_session_date(), 'Active')
        RETURNING * INTO v_session;
    END IF;

    -- Rate Limiting per IP / Client Fingerprint untuk mencegah spam bot
    v_client_key := COALESCE(
        NULLIF(trim(p_client_fingerprint), ''),
        NULLIF(split_part(COALESCE(current_setting('request.headers', true)::json->>'x-forwarded-for', ''), ',', 1), ''),
        'anon-global'
    );

    IF v_client_key <> 'anon-global' THEN
        SELECT * INTO v_rate
        FROM public.queue_rate_limits
        WHERE client_key = v_client_key
        FOR UPDATE;

        IF FOUND THEN
            IF v_rate.session_id = v_session.id THEN
                IF EXTRACT(EPOCH FROM (NOW() - v_rate.last_taken_at)) < 15 THEN
                    RAISE EXCEPTION 'Mohon tunggu 15 detik sebelum mengambil nomor antrean lagi.';
                END IF;
                IF v_rate.ticket_count >= 5 THEN
                    RAISE EXCEPTION 'Batas pengambilan tiket per perangkat untuk sesi ini telah tercapai (maksimal 5 tiket).';
                END IF;
                UPDATE public.queue_rate_limits
                SET last_taken_at = NOW(), ticket_count = ticket_count + 1
                WHERE client_key = v_client_key;
            ELSE
                UPDATE public.queue_rate_limits
                SET session_id = v_session.id, last_taken_at = NOW(), ticket_count = 1
                WHERE client_key = v_client_key;
            END IF;
        ELSE
            INSERT INTO public.queue_rate_limits (client_key, session_id, last_taken_at, ticket_count)
            VALUES (v_client_key, v_session.id, NOW(), 1);
        END IF;
    END IF;

    -- Hitung jumlah antrean pada sesi aktif (selain yang dibatalkan)
    SELECT COUNT(*) INTO v_total_count
    FROM public.queues
    WHERE session_id = v_session.id AND status <> 'Cancelled';

    IF v_total_count >= v_settings.queue_limit THEN
        RAISE EXCEPTION 'Maaf, kuota antrean untuk sesi ini telah mencapai batas maksimum (% antrean).', v_settings.queue_limit;
    END IF;

    -- Hitung nomor urut berikutnya berdasarkan starting_number
    SELECT COALESCE(MAX(sequence_number) + 1, v_settings.starting_number)
    INTO v_next_seq
    FROM public.queues
    WHERE session_id = v_session.id;

    v_ticket_number := v_settings.queue_prefix || LPAD(v_next_seq::TEXT, 3, '0');

    -- Hitung antrean Waiting di depan + apakah ada yang sedang Called (Konsisten dengan get_ticket_by_token)
    SELECT COUNT(*) INTO v_waiting_ahead
    FROM public.queues
    WHERE session_id = v_session.id AND status = 'Waiting';

    SELECT COUNT(*) INTO v_has_called
    FROM public.queues
    WHERE session_id = v_session.id AND status = 'Called';

    INSERT INTO public.queues (
        session_id, sequence_number, ticket_number, visitor_name, status
    ) VALUES (
        v_session.id, v_next_seq, v_ticket_number, v_clean_name, 'Waiting'
    ) RETURNING * INTO v_new_queue;

    RETURN jsonb_build_object(
        'id', v_new_queue.id,
        'session_id', v_new_queue.session_id,
        'ticket_number', v_new_queue.ticket_number,
        'tracking_token', v_new_queue.tracking_token,
        'status', v_new_queue.status,
        'created_at', v_new_queue.created_at,
        'waiting_ahead', v_waiting_ahead,
        'queue_position', v_waiting_ahead + 1,
        'estimated_wait_minutes', (v_waiting_ahead + v_has_called) * v_settings.session_duration
    );
END;
$$;

-- 4.2 RPC: get_ticket_by_token (Konsisten Rumus Estimasi & Tidak Membocorkan Nama Pengunjung)
CREATE OR REPLACE FUNCTION public.get_ticket_by_token(p_token UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_queue public.queues%ROWTYPE;
    v_settings public.queue_settings%ROWTYPE;
    v_current_called VARCHAR(20);
    v_waiting_ahead INTEGER;
    v_has_called INTEGER;
BEGIN
    SELECT * INTO v_queue FROM public.queues WHERE tracking_token = p_token LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Tiket tidak ditemukan atau token tidak valid.';
    END IF;

    SELECT * INTO v_settings FROM public.queue_settings WHERE singleton_key = TRUE LIMIT 1;

    SELECT ticket_number INTO v_current_called
    FROM public.queues
    WHERE session_id = v_queue.session_id AND status = 'Called'
    LIMIT 1;

    v_has_called := CASE WHEN v_current_called IS NOT NULL THEN 1 ELSE 0 END;

    IF v_queue.status = 'Waiting' THEN
        SELECT COUNT(*) INTO v_waiting_ahead
        FROM public.queues
        WHERE session_id = v_queue.session_id
          AND status = 'Waiting'
          AND sequence_number < v_queue.sequence_number;
    ELSE
        v_waiting_ahead := 0;
    END IF;

    RETURN jsonb_build_object(
        'queue_id', v_queue.id,
        'session_id', v_queue.session_id,
        'ticket_number', v_queue.ticket_number,
        'status', v_queue.status,
        'created_at', v_queue.created_at,
        'called_at', v_queue.called_at,
        'completed_at', v_queue.completed_at,
        'currently_called', COALESCE(v_current_called, '-'),
        'waiting_ahead', v_waiting_ahead,
        'queue_position', CASE WHEN v_queue.status = 'Waiting' THEN v_waiting_ahead + 1 ELSE 0 END,
        'estimated_wait_minutes', CASE
            WHEN v_queue.status = 'Waiting' THEN (v_waiting_ahead + v_has_called) * COALESCE(v_settings.session_duration, 5)
            ELSE 0
        END,
        'photobooth_name', v_settings.photobooth_name,
        'near_turn_threshold', v_settings.near_turn_threshold
    );
END;
$$;

-- 4.3 RPC: get_public_display (Untuk Halaman /display dan Info Registrasi)
CREATE OR REPLACE FUNCTION public.get_public_display()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_session public.queue_sessions%ROWTYPE;
    v_settings public.queue_settings%ROWTYPE;
    v_current_called VARCHAR(20);
    v_called_at TIMESTAMPTZ;
    v_next_queues JSONB;
    v_waiting_count INTEGER;
    v_total_active INTEGER;
BEGIN
    SELECT * INTO v_settings FROM public.queue_settings WHERE singleton_key = TRUE LIMIT 1;
    SELECT * INTO v_session FROM public.queue_sessions WHERE status = 'Active' LIMIT 1;

    IF v_session.id IS NULL THEN
        RETURN jsonb_build_object(
            'photobooth_name', v_settings.photobooth_name,
            'logo_url', v_settings.logo_url,
            'operational_status', v_settings.operational_status,
            'session_duration', v_settings.session_duration,
            'queue_limit', v_settings.queue_limit,
            'currently_called', NULL,
            'next_queues', '[]'::jsonb,
            'waiting_count', 0,
            'total_active', 0
        );
    END IF;

    SELECT ticket_number, called_at INTO v_current_called, v_called_at
    FROM public.queues
    WHERE session_id = v_session.id AND status = 'Called'
    LIMIT 1;

    SELECT COALESCE(jsonb_agg(t.ticket_number), '[]'::jsonb) INTO v_next_queues
    FROM (
        SELECT ticket_number
        FROM public.queues
        WHERE session_id = v_session.id AND status = 'Waiting'
        ORDER BY sequence_number ASC
        LIMIT 5
    ) t;

    SELECT COUNT(*) INTO v_waiting_count
    FROM public.queues
    WHERE session_id = v_session.id AND status = 'Waiting';

    SELECT COUNT(*) INTO v_total_active
    FROM public.queues
    WHERE session_id = v_session.id AND status <> 'Cancelled';

    RETURN jsonb_build_object(
        'session_id', v_session.id,
        'photobooth_name', v_settings.photobooth_name,
        'logo_url', v_settings.logo_url,
        'operational_status', v_settings.operational_status,
        'session_duration', v_settings.session_duration,
        'queue_limit', v_settings.queue_limit,
        'currently_called', v_current_called,
        'called_at', v_called_at,
        'next_queues', v_next_queues,
        'waiting_count', v_waiting_count,
        'total_active', v_total_active
    );
END;
$$;

-- 4.4 RPC: save_push_subscription
CREATE OR REPLACE FUNCTION public.save_push_subscription(p_token UUID, p_subscription JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_queue_id UUID;
BEGIN
    SELECT id INTO v_queue_id FROM public.queues WHERE tracking_token = p_token LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Token antrean tidak ditemukan.';
    END IF;

    INSERT INTO public.push_subscriptions (queue_id, subscription, notified_near_turn, notified_called)
    VALUES (v_queue_id, p_subscription, FALSE, FALSE)
    ON CONFLICT (queue_id)
    DO UPDATE SET subscription = EXCLUDED.subscription, created_at = NOW();

    RETURN TRUE;
END;
$$;

-- 4.5 RPC: admin_next_queue (Wajib terverifikasi public.is_admin())
CREATE OR REPLACE FUNCTION public.admin_next_queue()
RETURNS public.queues
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_session public.queue_sessions%ROWTYPE;
    v_active_called public.queues%ROWTYPE;
    v_next_queue public.queues%ROWTYPE;
BEGIN
    IF NOT public.is_admin() THEN
        RAISE EXCEPTION 'Forbidden: Hanya akun yang terdaftar di admin_users yang dapat memanggil antrean.';
    END IF;

    SELECT * INTO v_session FROM public.queue_sessions WHERE status = 'Active' LIMIT 1 FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Tidak ada sesi antrean yang aktif.';
    END IF;

    SELECT * INTO v_active_called
    FROM public.queues
    WHERE session_id = v_session.id AND status = 'Called'
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION 'Masih ada antrean aktif yang sedang dipanggil (%). Selesaikan (Complete) atau lewati (Skip) terlebih dahulu.', v_active_called.ticket_number;
    END IF;

    SELECT * INTO v_next_queue
    FROM public.queues
    WHERE session_id = v_session.id AND status = 'Waiting'
    ORDER BY sequence_number ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Tidak ada antrean berstatus Waiting untuk dipanggil.';
    END IF;

    UPDATE public.queues
    SET status = 'Called'
    WHERE id = v_next_queue.id
    RETURNING * INTO v_next_queue;

    RETURN v_next_queue;
END;
$$;

-- 4.6 RPC: admin_reset_queue (Menangani Antrean Tersisa Agar Tidak Menggantung di Sesi Closed)
CREATE OR REPLACE FUNCTION public.admin_reset_queue(p_auto_close_remaining BOOLEAN DEFAULT TRUE)
RETURNS public.queue_sessions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_active_session public.queue_sessions%ROWTYPE;
    v_remaining_count INTEGER;
    v_new_session public.queue_sessions%ROWTYPE;
BEGIN
    IF NOT public.is_admin() THEN
        RAISE EXCEPTION 'Forbidden: Hanya admin terdaftar yang dapat mereset sesi antrean.';
    END IF;

    SELECT * INTO v_active_session
    FROM public.queue_sessions
    WHERE status = 'Active'
    LIMIT 1
    FOR UPDATE;

    IF FOUND THEN
        SELECT COUNT(*) INTO v_remaining_count
        FROM public.queues
        WHERE session_id = v_active_session.id
          AND status IN ('Waiting', 'Called');

        IF v_remaining_count > 0 AND NOT p_auto_close_remaining THEN
            RAISE EXCEPTION 'Masih terdapat % antrean berstatus Waiting/Called pada sesi ini. Selesaikan terlebih dahulu atau aktifkan opsi pembatalan otomatis.', v_remaining_count;
        END IF;

        -- Bersihkan antrean yang masih menggantung agar tidak tertinggal dalam status aktif di sesi Closed
        UPDATE public.queues
        SET status = 'Completed'
        WHERE session_id = v_active_session.id AND status = 'Called';

        UPDATE public.queues
        SET status = 'Cancelled'
        WHERE session_id = v_active_session.id AND status = 'Waiting';

        UPDATE public.queue_sessions
        SET status = 'Closed', ended_at = NOW()
        WHERE id = v_active_session.id;
    END IF;

    INSERT INTO public.queue_sessions (session_date, status, started_at)
    VALUES (public.local_session_date(), 'Active', NOW())
    RETURNING * INTO v_new_session;

    -- Reset state tabel sinkronisasi publik
    UPDATE public.public_queue_sync
    SET session_id = v_new_session.id,
        currently_called = NULL,
        waiting_count = 0,
        updated_at = NOW()
    WHERE singleton_key = TRUE;

    RETURN v_new_session;
END;
$$;

-- ============================================================================
-- 5. ROW LEVEL SECURITY (RLS) POLICIES (Diperketat dengan public.is_admin())
-- ============================================================================

ALTER TABLE public.admin_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.queue_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.queue_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.queues ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.queue_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.push_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.public_queue_sync ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.queue_rate_limits ENABLE ROW LEVEL SECURITY;

-- Policies untuk admin_users: Hanya admin yang bisa melihat daftar admin
DROP POLICY IF EXISTS "Admin can read admin_users" ON public.admin_users;
CREATE POLICY "Admin can read admin_users"
    ON public.admin_users FOR SELECT
    TO authenticated
    USING (public.is_admin());

-- Policies untuk public_queue_sync: Publik (anon & authenticated) boleh SELECT (Tidak ada visitor_name!)
DROP POLICY IF EXISTS "Public can read public_queue_sync" ON public.public_queue_sync;
CREATE POLICY "Public can read public_queue_sync"
    ON public.public_queue_sync FOR SELECT
    TO anon, authenticated
    USING (true);

-- Policies untuk queue_settings: Publik dapat membaca konfigurasi dasar, HANYA Admin terdaftar yang dapat UPDATE
DROP POLICY IF EXISTS "Public can read queue_settings" ON public.queue_settings;
CREATE POLICY "Public can read queue_settings"
    ON public.queue_settings FOR SELECT
    TO anon, authenticated
    USING (true);

DROP POLICY IF EXISTS "Admin can update queue_settings" ON public.queue_settings;
CREATE POLICY "Admin can update queue_settings"
    ON public.queue_settings FOR UPDATE
    TO authenticated
    USING (public.is_admin())
    WITH CHECK (public.is_admin());

-- Policies untuk queue_sessions: Publik dapat membaca sesi, HANYA Admin terdaftar yang dapat mengubah
DROP POLICY IF EXISTS "Public can read queue_sessions" ON public.queue_sessions;
CREATE POLICY "Public can read queue_sessions"
    ON public.queue_sessions FOR SELECT
    TO anon, authenticated
    USING (true);

DROP POLICY IF EXISTS "Admin full access queue_sessions" ON public.queue_sessions;
CREATE POLICY "Admin full access queue_sessions"
    ON public.queue_sessions FOR ALL
    TO authenticated
    USING (public.is_admin())
    WITH CHECK (public.is_admin());

-- Policies untuk queues:
-- HANYA Admin terdaftar (public.is_admin()) yang bisa SELECT, INSERT, UPDATE.
-- DELETE dilarang untuk menjaga keutuhan riwayat dan audit (PRD Bab 12.5).
DROP POLICY IF EXISTS "Admin full access queues" ON public.queues;
DROP POLICY IF EXISTS "Admin select queues" ON public.queues;
DROP POLICY IF EXISTS "Admin update queues" ON public.queues;

CREATE POLICY "Admin select queues"
    ON public.queues FOR SELECT
    TO authenticated
    USING (public.is_admin());

CREATE POLICY "Admin update queues"
    ON public.queues FOR UPDATE
    TO authenticated
    USING (public.is_admin())
    WITH CHECK (public.is_admin());

-- Policies untuk queue_history: Hanya Admin terdaftar yang dapat membaca jejak audit (Tidak boleh diubah/dihapus)
DROP POLICY IF EXISTS "Admin can read queue_history" ON public.queue_history;
CREATE POLICY "Admin can read queue_history"
    ON public.queue_history FOR SELECT
    TO authenticated
    USING (public.is_admin());

-- Policies untuk push_subscriptions: Hanya Admin terdaftar
DROP POLICY IF EXISTS "Admin can read push_subscriptions" ON public.push_subscriptions;
CREATE POLICY "Admin can read push_subscriptions"
    ON public.push_subscriptions FOR SELECT
    TO authenticated
    USING (public.is_admin());

-- Berikan izin eksekusi RPC
GRANT EXECUTE ON FUNCTION public.is_admin() TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.local_session_date() TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.take_queue(VARCHAR, VARCHAR) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_ticket_by_token(UUID) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_public_display() TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.save_push_subscription(UUID, JSONB) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_next_queue() TO authenticated;
GRANT EXECUTE ON FUNCTION public.admin_reset_queue(BOOLEAN) TO authenticated;

-- ============================================================================
-- 6. SUPABASE REALTIME CONFIGURATION
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime' AND tablename = 'queues'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.queues;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime' AND tablename = 'public_queue_sync'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.public_queue_sync;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime' AND tablename = 'queue_sessions'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.queue_sessions;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime' AND tablename = 'queue_settings'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.queue_settings;
    END IF;
END $$;
