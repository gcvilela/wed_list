import { Request, Response, NextFunction } from "express";
import { normalizeInput } from "../utils/crypto";

/**
 * ROUND 70: Connection Dropout Handling
 */
export const connectionDropoutHandler = (req: Request, res: Response, next: NextFunction) => {
  req.on('aborted', () => {
    console.warn(`Segurança: Conexão abortada pelo cliente: ${req.ip}`);
  });
  next();
};

/**
 * ROUND 124: Reject empty bodies on POST requests
 */
export const rejectEmptyBody = (req: Request, res: Response, next: NextFunction) => {
  if (req.method === 'POST' && req.headers['content-length'] === '0') {
    return res.status(400).json({ error: "Payload obrigatório." });
  }
  next();
};

/**
 * ROUND 76-85, 98, 106, 108, 109, 116-120: Strict Validation Middleware
 */
export const strictValidation = (req: Request, res: Response, next: NextFunction) => {
  // ROUND 109: Normalize all inputs (NFC)
  req.body = normalizeInput(req.body);
  req.query = normalizeInput(req.query);

  const checkValue = (val: any, depth = 0): boolean => {
    if (depth > 5) return false; // ROUND 98
    if (val === null || val === undefined) return true;
    
    if (typeof val === 'string') {
      // Basic checks (Null byte, whitespace, zero-width)
      if (val.includes('\0') || val.trim().length === 0) return false;
      if (/[\u200B-\u200D\uFEFF]/.test(val)) return false;
      
      // ROUND 117 & 119: Strip RTLO and BIDI Control characters
      if (/[\u202E\u202A-\u202E\u2066-\u2069]/.test(val)) return false;

      // ROUND 116: Homoglyph / Mixed Script Detection
      const hasLatin = /[a-zA-Z]/.test(val);
      const hasNonLatin = /[^\u0000-\u007F]/.test(val);
      if (hasLatin && hasNonLatin && !/[\u00C0-\u017F]/.test(val)) {
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
      return val.every(item => checkValue(item, depth + 1));
    }
    
    if (typeof val === 'object') {
      // ROUND 107: length property injection
      if ('length' in val && typeof val.length !== 'number') return false;
      return Object.values(val).every(item => checkValue(item, depth + 1));
    }
    
    return true;
  };

  // ROUND 108: Reject HPP on query params
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
