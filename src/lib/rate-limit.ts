import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

export const rateLimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "10 s"),
  analytics: true,
  prefix: "@upstash/ratelimit",
});


const requests = new Map<string, { count: number; lastReset: number }>();
const WINDOW_MS = 60 * 1000; 
const MAX_REQUESTS = 10;

export function simpleRateLimit(identifier: string): {
  success: boolean;
  remaining: number;
} {
  const now = Date.now();
  const record = requests.get(identifier);

  if (!record || now - record.lastReset > WINDOW_MS) {
    requests.set(identifier, { count: 1, lastReset: now });
    return { success: true, remaining: MAX_REQUESTS - 1 };
  }

  if (record.count >= MAX_REQUESTS) {
    return { success: false, remaining: 0 };
  }

  record.count++;
  return { success: true, remaining: MAX_REQUESTS - record.count };
}
