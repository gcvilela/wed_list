import { Gift } from "../types";
import { GiftCard } from "./GiftCard";

interface GiftGridProps {
  gifts: Gift[];
  onGiftSelect: (gift: Gift) => void;
}

export function GiftGrid({ gifts, onGiftSelect }: GiftGridProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      {gifts.map((gift) => (
        <GiftCard 
          key={gift.id} 
          gift={gift} 
          onSelect={onGiftSelect} 
        />
      ))}
    </div>
  );
}
