import { Request, Response, NextFunction } from "express";

/**
 * ROUND 13, 14, 60 & 62: Reinforced Security Headers
 */
export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  
  // ROUND 114: Vary Header protection (Cache Integrity)
  res.setHeader("Vary", "Origin, User-Agent");

  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin"); // ROUND 60

  const isApi = req.path.startsWith('/api');
  
  // Reinforced CSP
  res.setHeader("Content-Security-Policy", 
    `default-src 'self'; ` +
    `frame-ancestors ${isApi ? "'none'" : "'self'"}; ` +
    `script-src 'self' https://sdk.mercadopago.com; ` +
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; ` +
    `img-src 'self' data: https://*.mercadopago.com https://picsum.photos https://images.unsplash.com; ` +
    `font-src 'self' https://fonts.gstatic.com; ` +
    `connect-src 'self' https://*.mercadopago.com;`
  );
  
  if (isApi) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  
  next();
};
