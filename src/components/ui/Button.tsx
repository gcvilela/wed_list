import React from "react";
import { cn } from "../../lib/utils";

export interface ButtonProps extends React.ComponentPropsWithoutRef<"button"> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost';
}

export function Button({ variant = 'primary', className, children, ...props }: ButtonProps) {
  const variants = {
    primary: "bg-wedding-sage text-white hover:bg-wedding-sage/90 uppercase tracking-widest text-xs",
    secondary: "bg-wedding-sage-light text-wedding-sage hover:bg-wedding-sage-light/80 uppercase tracking-widest text-xs",
    outline: "border border-wedding-gold text-wedding-gold hover:bg-wedding-gold hover:text-white uppercase tracking-widest text-xs",
    ghost: "text-wedding-dark hover:bg-wedding-sage-light uppercase tracking-widest text-xs"
  };

  return (
    <button
      className={cn(
        "px-6 py-2.5 rounded-xl font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed",
        variants[variant],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}
