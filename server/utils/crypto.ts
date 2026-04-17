import crypto from "crypto";

/**
 * ROUND 9 & 111: Timing Attack Protection Helper
 */
export const safeCompare = (a: string, b: string): boolean => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
};

/**
 * ROUND 109: Unicode Normalization Helper (NFC)
 */
export const normalizeInput = (val: any): any => {
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

/**
 * ROUND 122: Map size management to prevent OOM
 */
export const cleanMap = (map: Map<any, any>, maxSize: number): void => {
  if (map.size > maxSize) {
    const firstKey = map.keys().next().value;
    if (firstKey) map.delete(firstKey);
  }
};
