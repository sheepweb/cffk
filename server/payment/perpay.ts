import type { PerpayConfig } from "@/lib/config-schemas";
import type { PaymentQueryResult, PaymentNotifyResult } from "./types";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MERCHANT_NO = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_RESPONSE_BYTES = 256 * 1024;

function decodeBase64Url(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
}

function hex(bytes: ArrayBuffer | Uint8Array) {
  return Array.from(new Uint8Array(bytes instanceof Uint8Array ? bytes : bytes)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes: Uint8Array) {
  return hex(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)));
}

async function hmac(secret: string, text: string) {
  const key = await crypto.subtle.importKey("raw", decodeBase64Url(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text)));
}

function constantTimeEqual(left: string, right: string) {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

async function readResponseJson(response: Response) {
  if (!/^application\/json(?:;|$)/i.test(response.headers.get("content-type") ?? "")) throw new Error("PERPAY_INVALID_RESPONSE");
  if (!response.body) throw new Error("PERPAY_INVALID_RESPONSE");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw new Error("PERPAY_RESPONSE_TOO_LARGE");
      chunks.push(next.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as Record<string, unknown>; } catch { throw new Error("PERPAY_INVALID_RESPONSE"); }
}

function safeApiCode(value: unknown) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,80}$/.test(value) ? value.toUpperCase().replace(/-/g, "_") : "REQUEST_FAILED";
}

function targetPath(path: string) {
  return path.startsWith("/") ? path : `/${path}`;
}

async function request(config: PerpayConfig, method: string, path: string, body?: unknown) {
  const target = targetPath(path);
  const bytes = body === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(body));
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce = btoa(String.fromCharCode(...nonceBytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const signature = await hmac(config.apiSecret, ["PERPAY-HMAC-SHA256", "v1", method.toUpperCase(), target, timestamp, nonce, "default", await sha256(bytes)].join("\n"));
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(`${config.baseUrl}${target}`, {
      method: method.toUpperCase(),
      headers: { "content-type": "application/json", "X-PerPay-Client-Id": "default", "X-PerPay-Timestamp": timestamp, "X-PerPay-Nonce": nonce, "X-PerPay-Signature-Version": "v1", "X-PerPay-Signature": signature },
      ...(bytes.length ? { body: bytes } : {}), redirect: "error", signal: controller.signal,
    });
    const payload = await readResponseJson(response);
    if (!response.ok) {
      const error = payload.error as Record<string, unknown> | undefined;
      throw new Error(`PERPAY_API_${response.status}_${safeApiCode(error?.code)}`);
    }
    if (!payload.data || typeof payload.data !== "object") throw new Error("PERPAY_REQUEST_FAILED");
    return payload.data as Record<string, unknown>;
  } finally { clearTimeout(timeout); }
}

function result(values: Partial<PaymentNotifyResult> & Pick<PaymentNotifyResult, "verified" | "status" | "message">): PaymentNotifyResult {
  return { provider: "PERPAY", ...values };
}

export function createPerpayAdapter(config: PerpayConfig) {
  return {
    create: async (input: { orderNo: string; amount: number; subject: string; notifyUrl: string; returnUrl: string }) => {
      const data = await request(config, "POST", "/api/v1/orders", { idempotency_key: `cffk:${input.orderNo}`, merchant_order_no: input.orderNo, amount_cents: input.amount, product_name: input.subject, notify_url: input.notifyUrl, return_url: input.returnUrl });
      const checkout = data.checkout as { checkout_url?: unknown } | undefined;
      if (!checkout || typeof checkout.checkout_url !== "string" || !checkout.checkout_url) throw new Error("PERPAY_CREATE_FAILED");
      const url = new URL(checkout.checkout_url);
      if (url.origin !== config.baseUrl || url.username || url.password || url.search || url.hash || !/^\/checkout\/pct1_[A-Za-z0-9_-]{43}$/.test(url.pathname)) throw new Error("PERPAY_CREATE_FAILED");
      if (typeof data.order_id !== "string" || !UUID.test(data.order_id)) throw new Error("PERPAY_CREATE_FAILED");
      return { mode: "redirect" as const, url: url.href, paymentOrderNo: data.order_id };
    },
    verify: async (input: { payload: Record<string, string>; rawBody?: string; rawBodyBytes?: Uint8Array; headers?: Headers }) => {
      const headers = input.headers;
      const version = headers?.get("X-PerPay-Webhook-Version");
      const keyId = headers?.get("X-PerPay-Webhook-Key-Id");
      const timestamp = headers?.get("X-PerPay-Webhook-Timestamp");
      const deliveryId = headers?.get("X-PerPay-Webhook-Delivery-Id");
      const eventId = headers?.get("X-PerPay-Webhook-Event-Id");
      const attempt = headers?.get("X-PerPay-Webhook-Attempt");
      const received = headers?.get("X-PerPay-Webhook-Signature");
      const bodyBytes = input.rawBodyBytes ?? new TextEncoder().encode(input.rawBody ?? "");
      if (version !== "1" || !keyId || !UUID.test(keyId) || !deliveryId || !UUID.test(deliveryId) || !eventId || !UUID.test(eventId) || !timestamp || !/^[1-9][0-9]*$/.test(timestamp) || !Number.isSafeInteger(Number(timestamp)) || Math.abs(Date.now() - Number(timestamp)) > 300000 || !attempt || !/^[1-9][0-9]{0,8}$/.test(attempt) || !received || !/^v1=[0-9a-f]{64}$/.test(received)) return result({ verified: false, status: "FAILED", message: "PERPAY_WEBHOOK_INVALID" });
      const expected = `v1=${await hmac(config.webhookSecret, ["perpay:webhook:v1", keyId, timestamp, deliveryId, eventId, attempt, await sha256(bodyBytes)].join("\n"))}`;
      if (!constantTimeEqual(received, expected)) return result({ verified: false, status: "FAILED", message: "PERPAY_WEBHOOK_VERIFY_FAILED" });
      let event: Record<string, unknown>;
      try { event = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes)); } catch { return result({ verified: false, status: "FAILED", message: "PERPAY_WEBHOOK_INVALID" }); }
      const eventType = typeof event.event_type === "string" ? event.event_type : "";
      if (event.schema !== "perpay:outbox-event:v2" || event.event_id !== eventId || !["PAYMENT_CONFIRMED", "PAYMENT_DISPUTED", "REFUND_UPDATED"].includes(eventType) || !UUID.test(String(event.order_id ?? "")) || !MERCHANT_NO.test(String(event.merchant_order_no ?? "")) || event.currency !== "CNY") return result({ verified: false, status: "FAILED", message: "PERPAY_WEBHOOK_INVALID" });
      const amount = Number(event.received_amount_cents ?? event.payable_amount_cents);
      return result({ verified: true, orderNo: String(event.merchant_order_no), paymentOrderNo: String(event.order_id), amount: Number.isSafeInteger(amount) && amount >= 0 ? amount : undefined, currency: "CNY", status: eventType === "PAYMENT_CONFIRMED" && event.payment_status === "CONFIRMED" ? "PAID" : eventType === "PAYMENT_DISPUTED" ? "FAILED" : "PENDING", message: "PERPAY_WEBHOOK" });
    },
    query: async (input: { orderNo: string; paymentOrderNo?: string; amount: number }): Promise<PaymentQueryResult> => {
      const path = input.paymentOrderNo && UUID.test(input.paymentOrderNo) ? `/api/v1/orders/${input.paymentOrderNo}` : `/api/v1/orders/by-merchant-no/${encodeURIComponent(input.orderNo)}`;
      try {
        const data = await request(config, "GET", path);
        if (data.merchant_order_no !== input.orderNo || data.currency !== "CNY") return { provider: "PERPAY", verified: false, orderNo: input.orderNo, paymentOrderNo: data.order_id, status: "PENDING", message: "PERPAY_QUERY_FAILED" };
        const received = Number(data.received_amount_cents ?? data.payable_amount_cents);
        const status = data.payment?.status === "CONFIRMED" ? "PAID" : data.payment?.status === "DISPUTED" ? "FAILED" : "PENDING";
        return { provider: "PERPAY", verified: true, orderNo: input.orderNo, paymentOrderNo: data.order_id, amount: Number.isSafeInteger(received) ? received : undefined, currency: data.currency, status, message: "PERPAY_QUERY" };
      } catch { return { provider: "PERPAY", verified: false, orderNo: input.orderNo, paymentOrderNo: input.paymentOrderNo, status: "PENDING", message: "PERPAY_QUERY_FAILED" }; }
    },
  };
}
