import { Request, Response } from "express";
import crypto from "crypto";
import { GIFTS_DATABASE, processedPayments } from "../database/mockDb";
import { safeCompare, cleanMap } from "../utils/crypto";
import { TIMING_PADDING_MS } from "../config/security";
import { rateLimitMap } from "../middlewares/rateLimiter";

/**
 * Handle checkout creation
 */
export const createPayment = async (req: Request, res: Response) => {
  const start = Date.now();
  try {
    const { giftId, payer, guestMessage } = req.body;
    
    // Type validation
    if (typeof giftId !== 'string' || typeof payer?.name !== 'string') {
      return res.status(400).json({ error: "Parâmetros inválidos." });
    }

    // Sanitization and length checks
    if (payer.name.length > 100 || (guestMessage && typeof guestMessage === 'string' && guestMessage.length > 500)) {
      return res.status(400).json({ error: "Dados de entrada excedem o limite de caracteres permitido." });
    }

    // ROUND 89, 90, 111: Timing Leak & Enumeration Protection
    let gift = null;
    for (const id in GIFTS_DATABASE) {
      if (safeCompare(id, giftId)) {
        gift = GIFTS_DATABASE[id];
        break;
      }
    }

    if (!gift || gift.status !== 'active') {
      const remaining = TIMING_PADDING_MS - (Date.now() - start);
      if (remaining > 0) await new Promise(r => setTimeout(r, remaining));
      return res.status(400).json({ error: "O presente selecionado não está disponível para contribuição no momento." });
    }

    // ROUND 67: Double-Spend Simulation
    if (gift.collected >= gift.price) {
      return res.status(400).json({ error: "Este presente já foi totalmente coletado. Obrigado!" });
    }

    console.log(`Segurança: Iniciando checkout para ${gift.title} - Valor validado: R$ ${gift.price}`);
    
    const paymentRef = crypto.randomUUID(); // ROUND 86
    const RECIPIENT_ID = process.env.ADMIN_RECIPIENT_ID || "DEFAULT_RECIPIENT";
    
    res.json({ 
      id: paymentRef,
      init_point: `https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=${paymentRef}`,
      recipient: RECIPIENT_ID 
    });
  } catch (error) {
    console.error("Erro no processamento do pagamento:", error);
    res.status(500).json({ error: "Erro interno no servidor de pagamentos" });
  }
};

/**
 * Handle payment webhooks
 */
export const handleWebhook = async (req: Request, res: Response) => {
  const ip = req.ip || "unknown";
  const now = Date.now();

  try {
    // ROUND 68: Webhook Expiration
    const timestamp = req.headers['x-timestamp']; 
    if (timestamp && (now - Number(timestamp)) > 300000) { 
       console.warn(`Segurança: Webhook expirado: ${timestamp}`);
       return res.sendStatus(400);
    }

    // ROUND 26: Signature Validation
    const signature = req.headers['x-signature'];
    const gatewaySecret = process.env.PAYMENT_GATEWAY_SECRET || "";
    if (!signature || !safeCompare(signature as string, gatewaySecret)) {
      console.warn("Segurança: Tentativa de Webhook Spoofing detectada!");
      const limit = rateLimitMap.get(ip);
      if (limit) limit.fraudCount++;
      return res.sendStatus(401);
    }

    // Payload validation
    const allowedKeys = ['status', 'giftId', 'payerName', 'message', 'id', 'amount', 'currency', 'metadata'];
    const bodyKeys = Object.keys(req.body);
    if (bodyKeys.some(key => !allowedKeys.includes(key))) {
      return res.sendStatus(400);
    }

    const { status, giftId, payerName, message, id: paymentId, amount, currency, metadata } = req.body;
    const normalizedStatus = status?.toLowerCase();

    // ROUND 58: PII Masking
    const maskName = (name: string) => name ? name.replace(/^(.{2})(.*)(.{2})$/, "$1***$3") : "Anônimo";
    const maskedPayer = maskName(payerName);

    // ROUND 96: Byte size check
    if (message && Buffer.byteLength(message, 'utf8') > 1000) {
      console.warn(`Segurança: Mensagem muito pesada de ${maskedPayer}`);
      return res.status(400).json({ error: "Mensagem muito grande." });
    }

    // ROUND 37, 97: Value validation
    if (amount <= 0 || amount > Number.MAX_SAFE_INTEGER) {
      console.error(`Fraude: Valor de pagamento inválido de ${maskedPayer}: ${amount}`);
      const limit = rateLimitMap.get(ip);
      if (limit) limit.fraudCount++;
      return res.sendStatus(400);
    }

    // ROUND 33: Metadata check
    if (metadata?.giftId && metadata.giftId !== giftId) {
      console.error(`Fraude: Divergência de giftId de ${maskedPayer}`);
      return res.sendStatus(400);
    }

    // ROUND 27: Currency validation
    if (currency !== "BRL") {
      return res.sendStatus(400);
    }

    if (normalizedStatus === "refunded" || normalizedStatus === "charged_back") {
      console.warn(`Alerta Financeiro: Pagamento estornado para presente ${giftId}.`);
      return res.sendStatus(200);
    }

    if (normalizedStatus === "approved") {
      if (processedPayments.has(paymentId)) return res.sendStatus(200);

      // ROUND 23, 71-75, 111: Gift Lookup
      let gift = null;
      for (const id in GIFTS_DATABASE) {
        if (safeCompare(id, giftId)) {
          gift = GIFTS_DATABASE[id];
          break;
        }
      }

      if (!gift || gift.status !== 'active') {
        return res.sendStatus(403);
      }

      // ROUND 66: Overfunding check
      if (gift.collected + amount > gift.price) {
         console.warn(`Segurança: Pagamento excessivo para ${gift.title}`);
      }

      // Atomic update simulation
      gift.collected += amount;
      if (gift.collected >= gift.price) {
        gift.status = 'completed';
      }

      processedPayments.set(paymentId, now);
      cleanMap(processedPayments, 10000); // MAX_CACHE_SIZE
      console.log(`Sucesso: Pagamento aprovado de ${maskedPayer} para ${gift.title}. Status: ${gift.status}`);
    }

    res.sendStatus(200);
  } catch (error) {
    console.error("Erro no webhook:", error);
    res.sendStatus(500);
  }
};
