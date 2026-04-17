import { Router } from "express";
import { createPayment, handleWebhook } from "../controllers/payment";
import { healthCheck } from "../controllers/system";
import { healthRateLimit, paymentRateLimit } from "../middlewares/rateLimiter";

const router = Router();

// Health Check
router.get("/health", healthRateLimit, healthCheck);

// Payments
router.post("/payments/create", paymentRateLimit, createPayment);
router.post("/payments/webhook", handleWebhook);

export default router;
