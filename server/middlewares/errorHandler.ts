import { Request, Response, NextFunction } from "express";

/**
 * ROUND 112: Standardized Body-Parser Error Handler
 */
export const bodyParserErrorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof SyntaxError && 'body' in err) {
    console.warn(`Segurança: Erro de parsing JSON de ${req.ip}`);
    return res.status(400).json({ error: "Payload JSON inválido." });
  }
  if (err && err.type === 'entity.too.large') {
    console.warn(`Segurança: Payload excedeu o limite de tamanho de ${req.ip}`);
    return res.status(400).json({ error: "Requisição inválida ou malformada." });
  }
  next(err);
};

/**
 * ROUND 10: Global Error Handler
 */
export const globalErrorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  const errorId = Math.random().toString(36).substr(2, 9);
  console.error(`[Error ${errorId}]`, err);
  res.status(500).json({ 
    error: "Ocorreu um erro interno de processamento.",
    code: errorId
  });
};
