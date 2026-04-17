import { Request, Response, NextFunction } from "express";
import { cleanMap } from "../utils/crypto";
import { 
  MAX_CACHE_SIZE, 
  FRAUD_THRESHOLD, 
  CHECKOUT_CREATION_LIMIT, 
  PAYMENT_LIMIT, 
  WINDOW_MS 
} from "../config/security";

const rateLimitMap = new Map<string, { count: number, resetAt: number, fraudCount: number }>();

/**
 * ROUND 28, 43, 122: Billing DoS & Fraud Velocity Protection
 */
export const paymentRateLimit = (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || "unknown";
  const now = Date.now();
  const limit = rateLimitMap.get(ip);

  if (limit && now < limit.resetAt) {
    if (limit.fraudCount >= FRAUD_THRESHOLD) {
      console.warn(`Segurança: IP ${ip} banido temporariamente por Fraud Velocity.`);
      return res.status(403).json({ error: "Acesso bloqueado por atividade suspeita." });
    }
    if (req.path === "/api/payments/create" && limit.count >= CHECKOUT_CREATION_LIMIT) {
       console.warn(`Segurança: Bloqueio de Carding/Velocity para IP: ${ip}`);
       return res.status(429).json({ error: "Limite de tentativas de checkout excedido. Tente em 15 minutos." });
    }
    if (limit.count >= PAYMENT_LIMIT) {
      return res.status(429).json({ error: "Muitas tentativas. Tente novamente em 15 minutos." });
    }
    limit.count++;
  } else {
    cleanMap(rateLimitMap, MAX_CACHE_SIZE); // ROUND 122
    rateLimitMap.set(ip, { count: 1, resetAt: now + WINDOW_MS, fraudCount: 0 });
  }
  next();
};

const healthRateLimitMap = new Map<string, { count: number, resetAt: number }>();

/**
 * ROUND 54: Strict Rate Limiter for Health Checks
 */
export const healthRateLimit = (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || "unknown";
  const now = Date.now();
  const limit = healthRateLimitMap.get(ip);
  if (limit && now < limit.resetAt) {
    if (limit.count > 10) return res.status(429).send("Too many health checks.");
    limit.count++;
  } else {
    cleanMap(healthRateLimitMap, MAX_CACHE_SIZE); // ROUND 122
    healthRateLimitMap.set(ip, { count: 1, resetAt: now + 60000 });
  }
  next();
};

// Exporting the map for manual fraud count increment if needed (though usually done in controller)
export { rateLimitMap };
