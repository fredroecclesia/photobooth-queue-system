import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.PUBLIC_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.PUBLIC_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured = Boolean(
  supabaseUrl &&
  supabaseAnonKey &&
  !supabaseUrl.includes('your-project-id')
);

export const supabase = isSupabaseConfigured
  ? createClient(supabaseUrl, supabaseAnonKey, {
      realtime: {
        params: {
          eventsPerSecond: 10,
        },
      },
    })
  : null;

/**
 * Sanitasi string HTML untuk mencegah Stored XSS saat merender ke DOM
 */
export function escapeHtml(value: unknown): string {
  const str = String(value ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Sanitasi sel CSV untuk mencegah CSV Formula Injection (=, +, -, @, tab, CR)
 * sekaligus meng-escape tanda kutip ganda sesuai RFC 4180.
 */
export function escapeCsvCell(value: unknown): string {
  let str = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * Fingerprint ringan perangkat klien untuk Rate Limiting take_queue
 */
export function getClientFingerprint(): string {
  if (typeof window === 'undefined') return 'server';
  const storageKey = 'pq_client_fp';
  try {
    let fp = window.localStorage.getItem(storageKey);
    if (!fp) {
      fp = 'fp-' + Math.random().toString(36).slice(2) + '-' + Date.now().toString(36);
      window.localStorage.setItem(storageKey, fp);
    }
    return fp;
  } catch {
    return 'fp-fallback-' + navigator.userAgent.length;
  }
}

/**
 * Memicu Supabase Edge Function send-push-notification secara non-blocking (PRD Bab 7 & 14)
 */
export async function triggerPushNotification(sessionId: string, calledQueueId: string): Promise<void> {
  if (!supabase) return;
  try {
    await supabase.functions.invoke('send-push-notification', {
      body: {
        session_id: sessionId,
        called_queue_id: calledQueueId,
      },
    });
  } catch (err) {
    // Kegagalan push notification tidak boleh menghentikan proses antrean (PRD Bab 14)
    console.warn('Push notification non-blocking warning:', err);
  }
}

/**
 * Helper Audio Announcement menggunakan Web Speech API (PRD Bab 6)
 */
export function speakQueueAnnouncement(
  ticketNumber: string,
  photoboothName = 'photobooth',
  options?: {
    voiceLang?: string;
    rate?: number;
    volume?: number;
  }
): Promise<boolean> {
  return new Promise((resolve) => {
    if (typeof window === 'undefined' || !('speechSynthesis' in window)) {
      resolve(false);
      return;
    }

    try {
      window.speechSynthesis.cancel();
      const spelledTicket = ticketNumber.split('').join(' ');
      const text = `Nomor antrean ${spelledTicket}, silakan menuju ${photoboothName}.`;
      const utterance = new SpeechSynthesisUtterance(text);

      const voices = window.speechSynthesis.getVoices();
      const targetLang = options?.voiceLang || import.meta.env.PUBLIC_DEFAULT_SPEECH_LANG || 'id-ID';
      const matchedVoice =
        voices.find((v) => v.name === targetLang || v.lang === targetLang) ||
        voices.find((v) => v.lang.toLowerCase().startsWith('id')) ||
        voices[0];

      if (matchedVoice) {
        utterance.voice = matchedVoice;
        utterance.lang = matchedVoice.lang;
      } else {
        utterance.lang = 'id-ID';
      }

      utterance.rate = Number(options?.rate ?? 1.0);
      utterance.volume = Number(options?.volume ?? 1.0);
      utterance.onend = () => resolve(true);
      utterance.onerror = () => resolve(false);

      window.speechSynthesis.speak(utterance);
    } catch (e) {
      console.error('Web Speech API error:', e);
      resolve(false);
    }
  });
}
