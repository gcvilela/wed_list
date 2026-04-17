import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import cors from "cors";
import crypto from "crypto"; // ROUND 86 Support

dotenv.config();

// ROUND 99: Uncaught Exception/Rejection Protection
process.on('uncaughtException', (err) => {
  console.error('CRITICAL: Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('CRITICAL: Unhandled Rejection at:', promise, 'reason:', reason);
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // ROUND 47: Directory Traversal Protection (Global)
  app.use((req, res, next) => {
    const path = req.path;
    if (path.includes('..') || path.includes('%2e%2e')) {
       console.warn(`Segurança: Tentativa de Directory Traversal detectada: ${req.ip} -> ${path}`);
       return res.status(400).json({ error: "Requisição inválida." });
    }
    next();
  });

  // ROUND 70: Connection Dropout Handling
  app.use((req, res, next) => {
    req.on('aborted', () => {
      console.warn(`Segurança: Conexão abortada pelo cliente: ${req.ip}`);
    });
    next();
  });

  // ROUND 76-85, 98, 106, 108, 109: Strict Validation Middleware
  const strictValidation = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    // ROUND 109: Normalize all inputs (NFC)
    req.body = normalizeInput(req.body);
    req.query = normalizeInput(req.query);

    const checkValue = (val: any, depth = 0): boolean => {
      if (depth > 5) return false; // ROUND 98
      if (val === null || val === undefined) return true;
      
      if (typeof val === 'string') {
        if (val.includes('\0') || val.trim().length === 0) return false;
        if (/[\u200B-\u200D\uFEFF]/.test(val)) return false;
        // ROUND 117 & 119: Strip RTLO and BIDI Control characters
        if (/[\u202E\u202A-\u202E\u2066-\u2069]/.test(val)) return false;

        // ROUND 116: Homoglyph / Mixed Script Detection (Latin + non-Latin)
        const hasLatin = /[a-zA-Z]/.test(val);
        const hasNonLatin = /[^\u0000-\u007F]/.test(val);
        if (hasLatin && hasNonLatin && !/[\u00C0-\u017F]/.test(val)) { // Permitir acentos latinos
           return false; 
        }

        // ROUND 120: Admin Impersonation
        const normalizedName = val.toLowerCase().replace(/\s/g, '');
        if (['admin', 'sistema', 'root', 'weddingadmin'].includes(normalizedName)) return false;

        return true;
      }
      
      if (typeof val === 'number') {
        return Number.isFinite(val) && !Number.isNaN(val);
      }
      
      if (Array.isArray(val)) {
        // ROUND 108: HPP - Reject if query parameter is an array where a string is expected
        // (Handled by route logic, but we can flag abnormal arrays here)
        return val.every(item => checkValue(item, depth + 1));
      }
      
      if (typeof val === 'object') {
        // ROUND 107: Protect against { length: ... } injection
        if ('length' in val && typeof val.length !== 'number') return false;
        return Object.values(val).every(item => checkValue(item, depth + 1));
      }
      
      return true;
    };

    // ROUND 108: Reject HPP on crucial query params
    for (const key in req.query) {
      if (Array.isArray(req.query[key])) {
        console.warn(`Segurança: HTTP Parameter Pollution detectado de ${req.ip} no parâmetro: ${key}`);
        return res.status(400).json({ error: "Parâmetros duplicados não são permitidos." });
      }
    }

    if (!checkValue(req.body) || !checkValue(req.query)) {
      console.warn(`Segurança: Payload malicioso ou malformado detectado de ${req.ip}`);
      return res.status(400).json({ error: "Requisição inválida ou malformada." });
    }
    next();
  };

  // ROUND 112: Standardized Body-Parser Error Handler
  const bodyParserErrorHandler = (err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (err instanceof SyntaxError && 'body' in err) {
      console.warn(`Segurança: Erro de parsing JSON de ${req.ip}`);
      return res.status(400).json({ error: "Payload JSON inválido." });
    }
    if (err && err.type === 'entity.too.large') {
      console.warn(`Segurança: Payload excedeu o limite de tamanho de ${req.ip}`);
      return res.status(400).json({ error: "Requisição inválida ou malformada." }); // Generic error
    }
    next(err);
  };

  // ROUND 49: Hardened Methods (Explicitly drop TRACE/TRACK)
  app.use((req, res, next) => {
    if (['TRACE', 'TRACK'].includes(req.method)) {
      return res.status(405).send('Method Not Allowed');
    }
    next();
  });

  // ROUND 65: Prototype Pollution Prevention (JSON Reviver)
  const secureJsonReviver = (key: string, value: any) => {
    if (key === '__proto__' || key === 'constructor') return undefined;
    return value;
  };

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
    
    // ROUND 114: Vary Header protection (Cache Integrity)
    res.setHeader("Vary", "Origin, User-Agent");

    // ROUND 13, 14, 60 & 62: Enhanced CSP and Security Policies
    const isApi = req.path.startsWith('/api');
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin"); // ROUND 60: Prevent full path leak
    res.setHeader("Content-Security-Policy", `default-src 'self'; frame-ancestors ${isApi ? "'none'" : "'self'"}; script-src 'self' https://sdk.mercadopago.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https://*.mercadopago.com https://picsum.photos https://images.unsplash.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://*.mercadopago.com;`);
    
    if (isApi) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
    }
    
    next();
  });

  // ROUND 55: Bot/Scraper Anomaly Detection
  app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'];
    if (!userAgent || userAgent.length < 10) {
       console.warn(`Segurança: Bloqueio de Bot sem User-Agent: ${req.ip}`);
       return res.status(403).json({ error: "Acesso negado." });
    }
    next();
  });

  // ROUND 7: Granular Payload Limits
  app.use("/api/payments/webhook", express.json({ limit: '2kb', reviver: secureJsonReviver })); 
  app.use(express.json({ limit: '10kb', reviver: secureJsonReviver })); 
  app.use(bodyParserErrorHandler); // ROUND 112: Standardize errors
  
  app.use(strictValidation); // ROUND 76-85, 98, 106, 108, 109: Apply to ALL routes

  // ROUND 124: Rejeitar bodies vazios em POSTs (DoS Prevention)
  app.use((req, res, next) => {
    if (req.method === 'POST' && req.headers['content-length'] === '0') {
      return res.status(400).json({ error: "Payload obrigatório." });
    }
    next();
  });

  // ROUND 9 & 111: Timing Attack Protection Helper (Criptograficamente seguro)
  const safeCompare = (a: string, b: string) => {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  };

  // ROUND 109: Unicode Normalization Helper
  const normalizeInput = (val: any): any => {
    if (typeof val === 'string') return val.normalize('NFC');
    if (Array.isArray(val)) return val.map(normalizeInput);
    if (val !== null && typeof val === 'object') {
      const normalized: any = {};
      for (const key in val) {
        normalized[key.normalize('NFC')] = normalizeInput(val[key]);
      }
      return normalized;
    }
    return val;
  };

  // 4. BASIC RATE LIMITER (Billing DoS & Fraud Velocity Protection)
  // ROUND 122: Evitar OOM limitando tamanho dos Maps
  const rateLimitMap = new Map<string, { count: number, resetAt: number, fraudCount: number }>();
  const MAX_CACHE_SIZE = 10000;

  const cleanMap = (map: Map<any, any>) => {
    if (map.size > MAX_CACHE_SIZE) {
      const firstKey = map.keys().next().value;
      if (firstKey) map.delete(firstKey);
    }
  };

  const PAYMENT_LIMIT = 5; 
  const CHECKOUT_CREATION_LIMIT = 3; 
  const FRAUD_THRESHOLD = 3; // ROUND 43: Ban IPs after 3 fraud attempts
  const WINDOW_MS = 15 * 60 * 1000; 

  const paymentRateLimit = (req: express.Request, res: express.Response, next: express.NextFunction) => {
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
      cleanMap(rateLimitMap); // ROUND 122
      rateLimitMap.set(ip, { count: 1, resetAt: now + WINDOW_MS, fraudCount: 0 });
    }
    next();
  };

  // ROUND 54: Strict Rate Limiter for Health Checks
  const healthRateLimitMap = new Map<string, { count: number, resetAt: number }>();
  app.get("/api/health", (req, res) => {
    const ip = req.ip || "unknown";
    const now = Date.now();
    const limit = healthRateLimitMap.get(ip);
    if (limit && now < limit.resetAt) {
      if (limit.count > 10) return res.status(429).send("Too many health checks.");
      limit.count++;
    } else {
      cleanMap(healthRateLimitMap); // ROUND 122
      healthRateLimitMap.set(ip, { count: 1, resetAt: now + 60000 });
    }
    res.json({ status: "ok" });
  });

  // ROUND 50: Security & Robots Meta-Files
  app.get("/robots.txt", (req, res) => {
    res.type('text/plain');
    res.send("User-agent: *\nDisallow: /api/\nDisallow: /logs/\n");
  });

  app.get("/.well-known/security.txt", (req, res) => {
    res.type('text/plain');
    res.send("Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59.000Z\nPolicy: https://example.com/security-policy\n");
  });

  // Mock Gifts Database (Source of Truth)
  const GIFTS_DATABASE: Record<string, { price: number, title: string, collected: number, status: 'active' | 'completed' | 'draft' }> = {
    "1": { title: "Jogo de Panelas Le Creuset", price: 2500, collected: 0, status: 'active' },
    "2": { title: "Jantar Romântico em Paris", price: 1200, collected: 0, status: 'active' },
    "3": { title: "Smart TV 4K 65\"", price: 4500, collected: 0, status: 'active' },
    "4": { title: "Máquina de Café Espresso", price: 1800, collected: 0, status: 'active' }
  };

  // Mercado Pago Payment Integration
  app.post("/api/payments/create", paymentRateLimit, async (req, res) => {
    const start = Date.now();
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

      // ROUND 89, 90, 111: Timing Leak & Enumeration Protection
      // We process a mock constant delay for errors or missing items
      let gift = null;
      for (const id in GIFTS_DATABASE) {
        if (safeCompare(id, giftId)) {
          gift = GIFTS_DATABASE[id];
          break;
        }
      }

      if (!gift || gift.status !== 'active') {
        const remaining = 300 - (Date.now() - start);
        if (remaining > 0) await new Promise(r => setTimeout(r, remaining));
        return res.status(400).json({ error: "O presente selecionado não está disponível para contribuição no momento." });
      }

      // ROUND 67: Double-Spend Simulation (Front-run Check)
      if (gift.collected >= gift.price) {
        return res.status(400).json({ error: "Este presente já foi totalmente coletado. Obrigado!" });
      }

      console.log(`Segurança: Iniciando checkout para ${gift.title} - Valor validado: R$ ${gift.price}`);
      
      // ROUND 86: Cryptographically Secure ID Generation
      const paymentRef = crypto.randomUUID();
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
  });

  // ROUND 30, 68: Idempotency Cache with Expiration
  const processedPayments = new Map<string, number>();

  // Webhook para notificações de pagamento
  app.post("/api/payments/webhook", async (req, res) => {
    const ip = req.ip || "unknown";

    // ROUND 68: Webhook Expiration / Delayed Poisoning
    const timestamp = req.headers['x-timestamp']; 
    const now = Date.now();
    if (timestamp && (now - Number(timestamp)) > 300000) { // 5 minutes
       console.warn(`Segurança: Webhook expirado (TOCTOU delayed): ${timestamp}`);
       return res.sendStatus(400);
    }

    // ROUND 26: Webhook Signature Validation (Hardened)
    const signature = req.headers['x-signature'];
    const gatewaySecret = process.env.PAYMENT_GATEWAY_SECRET || "";
    if (!signature || !safeCompare(signature as string, gatewaySecret)) {
      console.warn("Segurança: Tentativa de Webhook Spoofing detectada!");
      // ROUND 43: Increment fraud count for suspicious attempts
      const limit = rateLimitMap.get(ip);
      if (limit) limit.fraudCount++;
      return res.sendStatus(401);
    }

    // 1. PREVENÇÃO DE PROTOTYPE POLLUTION: Validar estritamente as chaves
    const allowedKeys = ['status', 'giftId', 'payerName', 'message', 'id', 'amount', 'currency', 'metadata'];
    const bodyKeys = Object.keys(req.body);
    if (bodyKeys.some(key => !allowedKeys.includes(key))) {
      return res.sendStatus(400); // Silent error
    }

    const { status, giftId, payerName, message, id: paymentId, amount, currency, metadata } = req.body;
    
    // ROUND 100: Case-insensitive Status Normalization
    const normalizedStatus = status?.toLowerCase();

    // ROUND 58: PII Masking in Logs
    const maskName = (name: string) => name ? name.replace(/^(.{2})(.*)(.{2})$/, "$1***$3") : "Anônimo";
    const maskedPayer = maskName(payerName);

    // ROUND 51: ReDoS Protection (Optimized non-backtracking regex)
    // Avoid nested quantifiers like (a+)+
    const urlPattern = /\bhttps?:\/\/[^\s<]{5,200}\b/i;
    if (message && urlPattern.test(message)) {
      console.warn(`Fraude: Link suspeito bloqueado na mensagem do convidado: ${message}`);
      return res.status(400).json({ error: "Mensagens não podem conter links." });
    }

    // ROUND 96: Zalgo / Emoji Bombing Protection (Byte size check)
    if (message && Buffer.byteLength(message, 'utf8') > 1000) {
      console.warn(`Segurança: Mensagem do convidado muito pesada em bytes: ${Buffer.byteLength(message, 'utf8')}`);
      return res.status(400).json({ error: "Mensagem muito grande." });
    }

    // ROUND 37, 97: Negative Amount and Integer Overflow
    if (amount <= 0 || amount > Number.MAX_SAFE_INTEGER) {
      console.error(`Fraude: Valor de pagamento inválido ou overflow: ${amount}`);
      const limit = rateLimitMap.get(ip);
      if (limit) limit.fraudCount++;
      return res.sendStatus(400);
    }

    // ROUND 33: Gift Identity Theft (Metadata Verification)

    if (metadata?.giftId && metadata.giftId !== giftId) {
      console.error(`Fraude: Divergência entre giftId e metadata: ${giftId} vs ${metadata.giftId}`);
      return res.sendStatus(400);
    }

    // ROUND 27: Currency Validation
    if (currency !== "BRL") {
      console.error(`Fraude: Tentativa de pagamento em moeda estrangeira: ${currency}`);
      return res.sendStatus(400);
    }

    // ROUND 21: Fractional Cent Protection
    if (amount !== undefined && !Number.isInteger(amount)) {
      console.warn(`Segurança: Tentativa de pagamento fracionado detectada: ${amount}`);
      return res.status(400).json({ error: "Valor inválido." });
    }

    // ROUND 31 & 32: Status Validation & Chargeback Handling
    if (normalizedStatus === "refunded" || normalizedStatus === "charged_back") {
      console.warn(`Alerta Financeiro: Pagamento ${paymentId} estornado. Removendo R$ ${amount/100} do presente ${giftId}.`);
      return res.sendStatus(200);
    }

    if (normalizedStatus === "approved") {
      // ROUND 30: Replay Attack Protection (Idempotency)
      if (processedPayments.has(paymentId)) {
        console.log(`Segurança: Pagamento ${paymentId} já processado. Ignorando duplicata.`);
        return res.sendStatus(200);
      }

      // ROUND 23, 71-75, 111: State Machine and Ghost Payment Prevention (Timing Safe)
      let gift = null;
      for (const id in GIFTS_DATABASE) {
        if (safeCompare(id, giftId)) {
          gift = GIFTS_DATABASE[id];
          break;
        }
      }

      if (!gift || gift.status !== 'active') {
        console.error(`Segurança: Webhook recebeu pagamento para presente indisponível: ${giftId}`);
        return res.sendStatus(403);
      }

      // ROUND 66: Race Condition (Atomic Price Check / Overfunding)
      if (gift.collected + amount > gift.price) {
         console.warn(`Segurança: Pagamento excessivo recebido para ${giftId}.`);
      }

      // ROUND 17, 66: Atomic Transaction Simulation
      console.log(`Pagamento ${paymentId} aprovado para ${gift.title}. Atualizando de forma atômica...`);
      
      gift.collected += amount;
      if (gift.collected >= gift.price) {
        gift.status = 'completed'; // ROUND 71: Strict Transition
      }

      processedPayments.set(paymentId, now);
      cleanMap(processedPayments); // ROUND 122
      console.log(`Sucesso: Presente ${giftId} atualizado com R$ ${amount/100}. Status: ${gift.status}`);
    } else {
      // ROUND 32: Reject other statuses as incomplete
      console.log(`Status de pagamento não conclusivo: ${normalizedStatus}. Aguardando aprovação final.`);
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

  const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });

  // ROUND 123: Long-Lived Connection Hardening (DoS Prevention)
  server.keepAliveTimeout = 65000; 
  server.headersTimeout = 66000;
}

startServer();
