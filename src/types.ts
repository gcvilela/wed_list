export interface Gift {
  id: string;
  title: string;
  description?: string;
  imageUrl: string;
  price: number;
  collected: number;
  isInstallment?: boolean;
  category?: string;
}

export interface GuestMessage {
  id: string;
  guestName: string;
  giftId?: string;
  message: string;
  amount: number;
  timestamp: any;
}
