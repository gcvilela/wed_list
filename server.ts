import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import cors from "cors";

// 1. MODULE IMPORTS
import apiRoutes from "./server/routes/api";
import { securityHeaders } from "./server/middlewares/securityHeaders";
import { bodyParserErrorHandler, globalErrorHandler } from "./server/middlewares/errorHandler";
import { strictValidation, connectionDropoutHandler, rejectEmptyBody } from "./server/middlewares/validation";
import { robotsTxt, securityTxt } from "./server/controllers/system";

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
  const PORT = Number(process.env.PORT) || 3000;

  // 2. GLOBAL SECURITY HARDENING
  app.set('trust proxy', 1);
  app.disable("x-powered-by");

  // 3. GLOBAL MIDDLEWARES
  app.use(connectionDropoutHandler); // ROUND 70
  app.use(securityHeaders); // CSP, CORS, Vary, Cache
  
  // 4. CORS
  app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? process.env.APP_URL : '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-signature', 'x-timestamp'],
    credentials: true
  }));

  // 5. BODY PARSING & VALIDATION
  const secureJsonReviver = (key: string, value: any) => {
    if (key === '__proto__' || key === 'constructor') return undefined;
    return value;
  };

  app.use(express.json({ limit: '10kb', reviver: secureJsonReviver })); 
  app.use(bodyParserErrorHandler); // ROUND 112
  app.use(rejectEmptyBody); // ROUND 124
  app.use(strictValidation); // ROUND 76-85, 98, 106, 108, 109, 116-120

  // 6. API ROUTES
  app.use("/api", apiRoutes);

  // 7. SYSTEM META-ROUTES
  app.get("/robots.txt", robotsTxt);
  app.get("/.well-known/security.txt", securityTxt);

  // 8. VITE / STATIC SERVING
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, "dist");
    
    // ROUND 4: Log blocking
    app.use('/logs', (req, res) => res.sendStatus(403));

    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // 9. FINAL ERROR HANDLING
  app.use(globalErrorHandler);

  const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });

  // ROUND 123: Timeout Hardening
  server.keepAliveTimeout = 65000; 
  server.headersTimeout = 66000;
}

startServer();
