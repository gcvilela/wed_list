export interface Gift {
  id: string;
  title: string;
  price: number;
  collected: number;
  status: 'active' | 'completed' | 'draft';
}

/**
 * Mock Gifts Database (Source of Truth)
 */
export const GIFTS_DATABASE: Record<string, Gift> = {
  "1": { id: "1", title: "Jogo de Panelas Le Creuset", price: 2500, collected: 0, status: 'active' },
  "2": { id: "2", title: "Jantar Romântico em Paris", price: 1200, collected: 0, status: 'active' },
  "3": { id: "3", title: "Smart TV 4K 65\"", price: 4500, collected: 0, status: 'active' },
  "4": { id: "4", title: "Máquina de Café Espresso", price: 1800, collected: 0, status: 'active' }
};

/**
 * ROUND 30, 68: Idempotency Cache for processed payments
 * Map<PaymentID, Timestamp>
 */
export const processedPayments = new Map<string, number>();
