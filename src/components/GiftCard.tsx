import React from "react";
import { motion } from "motion/react";
import { Button } from "./ui/Button";
import { Gift } from "../types";
import { formatCurrency, cn } from "../lib/utils";
import { Heart } from "lucide-react";

export interface GiftCardProps {
  gift: Gift;
  onSelect: (gift: Gift) => void;
  key?: React.Key;
}

export function GiftCard({ gift, onSelect }: GiftCardProps) {
  const progress = Math.min((gift.collected / gift.price) * 100, 100);
  const isCompleted = progress >= 100;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      className="bg-white border border-wedding-border rounded flex flex-col p-4 shadow-sm hover:translate-y-[-4px] transition-all duration-300"
    >
      <div className="relative aspect-video bg-wedding-sage-light rounded-sm mb-4 overflow-hidden flex items-center justify-center">
        <img
          src={gift.imageUrl}
          alt={gift.title}
          referrerPolicy="no-referrer"
          className="w-full h-full object-cover"
        />
        
        {gift.isInstallment && (
          <div className="absolute top-2 left-2 bg-wedding-gold text-white text-[9px] uppercase font-bold px-2 py-0.5 rounded-full">
            Cotizado
          </div>
        )}
      </div>

      <div className="flex flex-col flex-1 gap-1">
        <h3 className="text-sm font-semibold text-wedding-dark">
          {gift.title}
        </h3>
        <span className="text-lg font-serif text-wedding-gold mb-3">
          {formatCurrency(gift.price)}
        </span>

        <div className="mt-auto space-y-2 mb-4">
          <div className="h-1 w-full bg-wedding-sage-light rounded-sm overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              whileInView={{ width: `${progress}%` }}
              transition={{ duration: 1.5, ease: "easeOut" }}
              className="h-full bg-wedding-sage"
            />
          </div>
          <div className="flex justify-between text-[11px] text-wedding-muted">
            <span>{Math.round(progress)}% Arrecadado</span>
            <span>{isCompleted ? "Garantido!" : `Faltam ${formatCurrency(gift.price - gift.collected)}`}</span>
          </div>
        </div>

        <button
          onClick={() => onSelect(gift)}
          disabled={isCompleted}
          className={cn(
            "w-full py-2.5 rounded-sm text-[12px] font-semibold tracking-wider transition-all duration-300 uppercase",
            isCompleted 
              ? "bg-wedding-sage-light text-wedding-muted cursor-not-allowed"
              : "bg-wedding-sage text-white hover:bg-wedding-sage/90"
          )}
        >
          {isCompleted ? "Presente já Garantido" : "Presentear"}
        </button>
      </div>
    </motion.div>
  );
}
