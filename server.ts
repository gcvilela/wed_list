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
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://sdk.mercadopago.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https://*.mercadopago.com https://picsum.photos https://images.unsplash.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://*.mercadopago.com; frame-ancestors 'self';");
    next();
  });

  app.use(express.json({ limit: '10kb' })); // Proteção contra payloads gigantescos

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
    const allowedKeys = ['status', 'giftId', 'payerName', 'message', 'id'];
    const bodyKeys = Object.keys(req.body);
    if (bodyKeys.some(key => !allowedKeys.includes(key))) {
      return res.sendStatus(400); // Silent error
    }

    const { status, giftId, payerName, message, id: paymentId } = req.body;
    
    if (status === "approved") {
      // 2. IDEMPOTÊNCIA: Verificar se este paymentId já foi processado
      // const alreadyProcessed = await db.collection('processed_payments').doc(paymentId).get();
      // if (alreadyProcessed.exists) return res.sendStatus(200);

      // 3. SEGURANÇA MONETÁRIA: Trabalhar com inteiros (centavos) se houver cálculos
      // const amountInCents = Math.round(Number(amount) * 100);

      console.log(`Pagamento ${paymentId} aprovado para o presente ${giftId}. Processando...`);
      
      // Marcar como processado para evitar Race Conditions em retentativas
      // await db.collection('processed_payments').doc(paymentId).set({ processedAt: new Date() });
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

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
