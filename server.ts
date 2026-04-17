import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // ROUND 6: Slowloris Mitigation (Strict Connection Timeouts)
  app.use((req, res, next) => {
    res.setTimeout(15000, () => {
      console.warn(`Segurança: Timeout de conexão para ${req.ip}`);
      res.status(408).send('Request Timeout');
    });
    next();
  });

  // ROUND 8: HTTP Verb Tampering (Allow only GET/POST)
  app.use((req, res, next) => {
    const allowedMethods = ['GET', 'POST'];
    if (!allowedMethods.includes(req.method)) {
      console.warn(`Segurança: Método ${req.method} bloqueado para ${req.ip}`);
      return res.status(405).json({ error: "Método não permitido." });
    }
    next();
  });

  // SECURITY HARDENING (Red Team Patch):
  app.set('trust proxy', 1);
  app.disable("x-powered-by");
  
  // 2. Strict CORS Policy
  app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? process.env.APP_URL : '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  }));

  // 3. Security Headers (Reinforced)
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    
    // ROUND 13 & 14: Enhanced CSP and Cache Control
    const isApi = req.path.startsWith('/api');
    res.setHeader("Content-Security-Policy", `default-src 'self'; frame-ancestors ${isApi ? "'none'" : "'self'"}; script-src 'self' 'unsafe-inline' https://sdk.mercadopago.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https://*.mercadopago.com https://picsum.photos https://images.unsplash.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://*.mercadopago.com;`);
    
    if (isApi) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
    }
    
    next();
  });

  // ROUND 7: Granular Payload Limits
  app.use("/api/payments/webhook", express.json({ limit: '2kb' })); // Webhooks são pequenos
  app.use(express.json({ limit: '10kb' })); // Limite geral

  // ROUND 9: Timing Attack Protection Helper
  const safeCompare = (a: string, b: string) => {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  };

  // 4. BASIC RATE LIMITER (Billing DoS Protection)
  const rateLimitMap = new Map<string, { count: number, resetAt: number }>();
  const PAYMENT_LIMIT = 5; // Máximo 5 tentativas
  const WINDOW_MS = 15 * 60 * 1000; // Por 15 minutos

  // CLEANUP PERIODICO (Blue Team Round 5 Patch): Evitar memory leak por IPs abusivos
  setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of rateLimitMap.entries()) {
      if (now > data.resetAt) rateLimitMap.delete(ip);
    }
  }, WINDOW_MS);

  const paymentRateLimit = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const ip = req.ip || "unknown";
    const now = Date.now();
    const limit = rateLimitMap.get(ip);

    if (limit && now < limit.resetAt) {
      if (limit.count >= PAYMENT_LIMIT) {
        return res.status(429).json({ error: "Muitas tentativas. Tente novamente em 15 minutos." });
      }
      limit.count++;
    } else {
      rateLimitMap.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    }
    next();
  };

  // API Routes
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
  });

  // Mock Gifts Database (Source of Truth)
  const GIFTS_DATABASE: Record<string, { price: number, title: string, status: 'active' | 'draft' }> = {
    "1": { title: "Jogo de Panelas Le Creuset", price: 2500, status: 'active' },
    "2": { title: "Jantar Romântico em Paris", price: 1200, status: 'active' },
    "3": { title: "Smart TV 4K 65\"", price: 4500, status: 'active' },
    "4": { title: "Máquina de Café Espresso", price: 1800, status: 'active' }
  };

  // Mercado Pago Payment Integration
  app.post("/api/payments/create", paymentRateLimit, async (req, res) => {
    try {
      const { giftId, payer, guestMessage } = req.body;
      
      // TYPE VALIDATION (Blue Team Round 2 Patch): Evitar Parameter Pollution
      if (typeof giftId !== 'string' || typeof payer?.name !== 'string') {
        return res.status(400).json({ error: "Parâmetros inválidos." });
      }

      // SANITIZAÇÃO DE ENTRADA (Blue Team Patch)
      if (payer.name.length > 100 || (guestMessage && typeof guestMessage === 'string' && guestMessage.length > 500)) {
        return res.status(400).json({ error: "Dados de entrada excedem o limite de caracteres permitido." });
      }

      // CRITICAL SECURITY (Red Team Patch): 
      // Use hasOwnProperty to prevent Prototype Access/Pollution (e.g., giftId = "__proto__")
      if (!Object.prototype.hasOwnProperty.call(GIFTS_DATABASE, giftId)) {
        return res.status(400).json({ error: "Presente inválido ou não encontrado" });
      }

      const gift = GIFTS_DATABASE[giftId];

      // BYPASS PROTECTION (Blue Team Patch): Não permitir compras de itens ocultos/draft
      if (gift.status !== 'active') {
        return res.status(403).json({ error: "Este presente não está disponível para contribuição." });
      }

      console.log(`Segurança: Iniciando checkout para ${gift.title} - Valor validado: R$ ${gift.price}`);
      
      // Simulação de resposta bem-sucedida
      res.json({ 
        id: "pref_secure_" + Math.random().toString(36).substr(2, 9),
        init_point: "https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=placeholder" 
      });
    } catch (error) {
      console.error("Erro no processamento do pagamento:", error);
      res.status(500).json({ error: "Erro interno no servidor de pagamentos" });
    }
  });

  // Webhook para notificações de pagamento
  app.post("/api/payments/webhook", async (req, res) => {
    // 1. PREVENÇÃO DE PROTOTYPE POLLUTION: Validar estritamente as chaves
    const allowedKeys = ['status', 'giftId', 'payerName', 'message', 'id', 'amount'];
    const bodyKeys = Object.keys(req.body);
    if (bodyKeys.some(key => !allowedKeys.includes(key))) {
      return res.sendStatus(400); // Silent error
    }

    const { status, giftId, payerName, message, id: paymentId, amount } = req.body;
    
    // ROUND 21: Fractional Cent Protection
    if (amount !== undefined && !Number.isInteger(amount)) {
      console.warn(`Segurança: Tentativa de pagamento fracionado detectada: ${amount}`);
      return res.status(400).json({ error: "Valor inválido." });
    }

    if (status === "approved") {
      // ROUND 22: Replay Attack Protection (Idempotency)
      // Simulação: Verificar em um cache/DB se o paymentId já existe
      // if (ProcessedPayments.has(paymentId)) return res.sendStatus(200);

      // ROUND 23: Ghost Payment Prevention
      if (!Object.prototype.hasOwnProperty.call(GIFTS_DATABASE, giftId)) {
        console.error(`Segurança: Webhook recebeu pagamento para presente inexistente: ${giftId}`);
        return res.sendStatus(404);
      }
      
      const gift = GIFTS_DATABASE[giftId];
      if (gift.status !== 'active') {
        console.error(`Segurança: Webhook recebeu pagamento para presente inativo: ${giftId}`);
        return res.sendStatus(403);
      }

      // ROUND 17: Transaction Simulation (Atomic Updates)
      console.log(`Pagamento ${paymentId} aprovado para ${gift.title}. Atualizando de forma atômica...`);
      
      // Simulação de transação:
      // await db.runTransaction(async (transaction) => {
      //   const giftRef = db.collection('gifts').doc(giftId);
      //   const giftDoc = await transaction.get(giftRef);
      //   const newCollected = giftDoc.data().collected + amount;
      //   transaction.update(giftRef, { collected: newCollected });
      //   transaction.set(db.collection('messages').doc(), { ... });
      // });

      console.log(`Sucesso: Presente ${giftId} atualizado com R$ ${amount/100}`);
    }

    res.sendStatus(200);
  });

  // Vite Integration
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, "dist");
    
    // BLOQUEIO DE ACESSO A LOGS (Blue Team Round 4 Patch)
    app.use('/logs', (req, res, next) => {
      res.sendStatus(403);
    });

    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // ROUND 10: Global Error Handler (Stack Trace Leakage Prevention)
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    const errorId = Math.random().toString(36).substr(2, 9);
    console.error(`[Error ${errorId}]`, err);
    res.status(500).json({ 
      error: "Ocorreu um erro interno de processamento.",
      code: errorId
    });
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
