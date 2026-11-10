// ============================================================================
// SUPABASE EDGE FUNCTION: send-push-notification (v1.1 - Hardened)
// Perbaikan Keamanan & Fungsional:
// 1. Memverifikasi JWT pengirim dan memastikan pemanggil adalah Admin terdaftar (is_admin()).
// 2. Deduplikasi pengiriman dengan flag notified_called & notified_near_turn agar tidak mengirim berulang.
// 3. Membersihkan langganan kedaluwarsa (HTTP 404 / 410 Gone) secara otomatis dari push_subscriptions.
// ============================================================================

import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.0";
import webpush from "npm:web-push@3.6.7";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const vapidPublicKey = Deno.env.get("PUBLIC_VAPID_PUBLIC_KEY");
    const vapidPrivateKey = Deno.env.get("VAPID_PRIVATE_KEY");
    const vapidSubject = Deno.env.get("VAPID_SUBJECT") || "mailto:admin@photobooth.local";

    // 1. Verifikasi autentikasi Admin pemanggil (Tidak boleh dipanggil sembarang orang dengan anon key)
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(
        JSON.stringify({ success: false, error: "Missing Authorization header" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: isAdmin, error: adminErr } = await userClient.rpc("is_admin");
    if (adminErr || !isAdmin) {
      return new Response(
        JSON.stringify({ success: false, error: "Forbidden: Hanya Admin yang dapat memicu push notification." }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!vapidPublicKey || !vapidPrivateKey) {
      return new Response(
        JSON.stringify({
          success: false,
          message: "VAPID keys belum dikonfigurasi pada environment Edge Function.",
        }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    webpush.setVapidDetails(vapidSubject, vapidPublicKey, vapidPrivateKey);

    const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);
    const { session_id, called_queue_id } = await req.json();

    // 2. Ambil pengaturan notifikasi dari baris singleton
    const { data: settings } = await supabaseAdmin
      .from("queue_settings")
      .select("*")
      .eq("singleton_key", true)
      .single();

    if (settings && !settings.notification_enabled) {
      return new Response(
        JSON.stringify({ success: true, message: "Notifikasi dinonaktifkan di pengaturan." }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const threshold = settings?.near_turn_threshold ?? 3;
    const notificationsToSend: Array<{
      queue_id: string;
      type: "called" | "near_turn";
      title: string;
      body: string;
      url: string;
    }> = [];

    // 3. Antrean yang dipanggil (Called)
    if (called_queue_id) {
      const { data: calledQueue } = await supabaseAdmin
        .from("queues")
        .select("*")
        .eq("id", called_queue_id)
        .single();

      if (calledQueue) {
        notificationsToSend.push({
          queue_id: calledQueue.id,
          type: "called",
          title: `Giliran Anda Dipanggil! (${calledQueue.ticket_number})`,
          body: `Nomor antrean ${calledQueue.ticket_number}, silakan menuju ${settings?.photobooth_name || "photobooth"} sekarang.`,
          url: `/track?t=${calledQueue.tracking_token}`,
        });
      }
    }

    // 4. Antrean Waiting yang tersisa <= threshold
    if (session_id) {
      const { data: waitingQueues } = await supabaseAdmin
        .from("queues")
        .select("*")
        .eq("session_id", session_id)
        .eq("status", "Waiting")
        .order("sequence_number", { ascending: true })
        .limit(threshold);

      if (waitingQueues && waitingQueues.length > 0) {
        waitingQueues.forEach((wq, index) => {
          const remaining = index + 1;
          notificationsToSend.push({
            queue_id: wq.id,
            type: "near_turn",
            title: `Antrean Mendekati Giliran (${wq.ticket_number})`,
            body: `Tersisa ${remaining} antrean lagi sebelum giliran Anda. Mohon bersiap di dekat area photobooth.`,
            url: `/track?t=${wq.tracking_token}`,
          });
        });
      }
    }

    if (notificationsToSend.length === 0) {
      return new Response(
        JSON.stringify({ success: true, sent_count: 0, expired_removed: 0 }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 5. Ambil push_subscriptions dan filter berdasarkan flag deduplikasi
    const targetQueueIds = notificationsToSend.map((n) => n.queue_id);
    const { data: subscriptions } = await supabaseAdmin
      .from("push_subscriptions")
      .select("id, queue_id, subscription, notified_near_turn, notified_called")
      .in("queue_id", targetQueueIds);

    let sentCount = 0;
    let expiredRemoved = 0;

    if (subscriptions && subscriptions.length > 0) {
      for (const subRow of subscriptions) {
        const payloadInfo = notificationsToSend.find((n) => n.queue_id === subRow.queue_id);
        if (!payloadInfo) continue;

        // Cegah pengiriman notifikasi berulang ke orang yang sama
        if (payloadInfo.type === "called" && subRow.notified_called) continue;
        if (payloadInfo.type === "near_turn" && subRow.notified_near_turn) continue;

        try {
          await webpush.sendNotification(
            subRow.subscription,
            JSON.stringify({
              title: payloadInfo.title,
              body: payloadInfo.body,
              url: payloadInfo.url,
              timestamp: new Date().toISOString(),
            })
          );
          sentCount++;

          // Tandai sudah dikirim agar tidak dikirim berulang pada panggilan berikutnya
          const updateFlags =
            payloadInfo.type === "called"
              ? { notified_called: true }
              : { notified_near_turn: true };

          await supabaseAdmin
            .from("push_subscriptions")
            .update(updateFlags)
            .eq("id", subRow.id);
        } catch (pushErr: any) {
          const statusCode = pushErr?.statusCode;
          // Hapus otomatis subscription yang sudah kedaluwarsa / dicabut izinnya (404 / 410 Gone)
          if (statusCode === 404 || statusCode === 410) {
            await supabaseAdmin.from("push_subscriptions").delete().eq("id", subRow.id);
            expiredRemoved++;
          } else {
            console.error(`Gagal mengirim push ke queue_id ${subRow.queue_id}:`, pushErr);
          }
        }
      }
    }

    return new Response(
      JSON.stringify({
        success: true,
        sent_count: sentCount,
        expired_removed: expiredRemoved,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error: any) {
    return new Response(
      JSON.stringify({ success: false, error: error.message }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
