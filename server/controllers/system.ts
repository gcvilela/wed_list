import { Request, Response } from "express";

/**
 * ROUND 54: Standard health check response
 */
export const healthCheck = (req: Request, res: Response) => {
  res.json({ status: "ok" });
};

/**
 * ROUND 50: Robots.txt controller
 */
export const robotsTxt = (req: Request, res: Response) => {
  res.type('text/plain');
  res.send("User-agent: *\nDisallow: /api/\nDisallow: /logs/\n");
};

/**
 * ROUND 50: Security.txt controller
 */
export const securityTxt = (req: Request, res: Response) => {
  res.type('text/plain');
  res.send("Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59.000Z\nPolicy: https://example.com/security-policy\n");
};
