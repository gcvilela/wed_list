/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect } from "react";
import { motion } from "motion/react";
import { Heart, Calendar, MapPin, Gift as GiftIcon, ArrowRight, MessageSquare, ShieldCheck } from "lucide-react";
import { GiftGrid } from "./components/GiftGrid";
import { Modal } from "./components/ui/Modal";
import { Button } from "./components/ui/Button";
import { Gift, GuestMessage } from "./types";
import { db } from "./firebase";
import { collection, onSnapshot, addDoc, query, orderBy, serverTimestamp, updateDoc, doc, increment } from "firebase/firestore";
import { formatCurrency } from "./lib/utils";

const MOCK_GIFTS: Gift[] = [
  {
    id: "1",
    title: "Jogo de Panelas Le Creuset",
    description: "Para prepararmos jantares inesquecíveis em nossa nova casa.",
    imageUrl: "https://picsum.photos/seed/pans/800/1000",
    price: 2500,
    collected: 1250,
    category: "Cozinha"
  },
  {
    id: "2",
    title: "Jantar Romântico em Paris",
    description: "Um presente para nossa lua de mel dos sonhos.",
    imageUrl: "https://picsum.photos/seed/paris/800/1000",
    price: 1200,
    collected: 600,
    category: "Lua de Mel"
  },
  {
    id: "3",
    title: "Smart TV 4K 65\"",
    description: "Para nossas sessões de cinema aos domingos.",
    imageUrl: "https://picsum.photos/seed/tv/800/1000",
    price: 4500,
    collected: 0,
    category: "Sala"
  },
  {
    id: "4",
    title: "Máquina de Café Espresso",
    description: "Para nos ajudar a acordar todos os dias com um sorriso.",
    imageUrl: "https://picsum.photos/seed/coffee/800/1000",
    price: 1800,
    collected: 1800,
    category: "Cozinha"
  }
];

export default function App() {
  const [gifts, setGifts] = useState<Gift[]>([]);
  const [selectedGift, setSelectedGift] = useState<Gift | null>(null);
  const [loading, setLoading] = useState(true);
  const [guestName, setGuestName] = useState("");
  const [guestMessage, setGuestMessage] = useState("");
  const [paying, setPaying] = useState(false);

  useEffect(() => {
    // Ideally we fetch from Firestore, but for demo we start with mock if empty
    const unsubscribe = onSnapshot(collection(db, "gifts"), (snapshot) => {
      const giftsData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as Gift));
      if (giftsData.length > 0) {
        setGifts(giftsData);
      } else {
        setGifts(MOCK_GIFTS);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const handlePayment = async () => {
    if (!selectedGift || !guestName) return;
    
    // ROUND 12: Input Sanitization (Pre-processing)
    const sanitizedName = guestName.trim().replace(/[<>]/g, "");
    const sanitizedMessage = guestMessage.trim().replace(/[<>]/g, "");

    setPaying(true);
    try {
      // ROUND 11: Image URL Validation (Defensive)
      const isValidImage = (url: string) => {
        try {
          const parsed = new URL(url);
          return ['https:', 'http:'].includes(parsed.protocol) && 
                 ['picsum.photos', 'images.unsplash.com'].some(d => parsed.hostname.includes(d));
        } catch { return false; }
      };

      if (!isValidImage(selectedGift.imageUrl)) {
        throw new Error("Origem da imagem do presente não é confiável.");
      }

      // 1. SECURITY: Request payment creation by Gift ID. 
      const response = await fetch("/api/payments/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          giftId: selectedGift.id,
          payer: { name: sanitizedName },
          guestMessage: sanitizedMessage
        })
      });
      
      const data = await response.json();
      
      if (!response.ok) throw new Error(data.error || "Erro ao criar checkout");

      // ROUND 15: Advanced Open Redirect Protection (Hardened Whitelist)
      const isAuthorizedDomain = (url: string) => {
        try {
          const parsed = new URL(url);
          const authorizedHostnames = [
            'www.mercadopago.com.br',
            'mercadopago.com.br'
          ];
          // Validar hostname exato ou subdomínio seguro
          return authorizedHostnames.includes(parsed.hostname) || 
                 parsed.hostname.endsWith('.mercadopago.com.br');
        } catch { return false; }
      };

      if (!isAuthorizedDomain(data.init_point)) {
        console.error(`Segurança: Tentativa de redirect para domínio suspeito: ${data.init_point}`);
        throw new Error("Link de pagamento inválido ou não autorizado.");
      }

      // SUCCESS: Backend will update Firestore via Webhook once payment is approved.
      alert(`Redirecionando para o Mercado Pago...\n(Sua mensagem será salva após a confirmação do pagamento)`);
      window.location.assign(data.init_point); // window.location.assign é mais seguro que .href direto em alguns contextos
      
    } catch (error) {
      console.error(error);
      alert(error instanceof Error ? error.message : "Erro ao processar. Tente novamente.");
    } finally {
      setPaying(false);
      setSelectedGift(null);
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-wedding-cream">
      {/* Header */}
      <header className="h-20 px-8 md:px-14 flex items-center justify-between bg-white border-b border-wedding-border sticky top-0 z-40">
        <div className="font-serif text-2xl tracking-widest text-wedding-gold">A&B</div>
        <nav className="hidden md:flex items-center gap-8">
          <a href="#" className="text-[13px] uppercase tracking-wider font-medium text-wedding-sage">Início</a>
          <a href="#" className="text-[13px] uppercase tracking-wider font-medium text-wedding-dark hover:text-wedding-sage transition-colors">Nossa História</a>
          <a href="#presentes" className="text-[13px] uppercase tracking-wider font-medium text-wedding-dark hover:text-wedding-sage transition-colors">Lista de Presentes</a>
          <Button variant="outline" className="rounded-full px-8 py-2 border-wedding-gold text-wedding-gold hover:bg-wedding-gold hover:text-white">RSVP</Button>
        </nav>
      </header>

      {/* Main Content Layout */}
      <main className="flex-1 grid grid-cols-1 lg:grid-cols-[400px_1fr] gap-10 p-8 md:p-14 max-w-[1600px] mx-auto w-full">
        
        {/* Left Column: Hero/Sidebar */}
        <aside className="hero-section flex flex-col justify-center gap-8">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="aspect-[4/5] bg-wedding-sage-light border-[8px] border-white shadow-xl shadow-black/5 relative overflow-hidden group"
          >
            <img 
              src="https://images.unsplash.com/photo-1519741497674-611481863552?auto=format&fit=crop&q=80&w=800" 
              className="w-full h-full object-cover grayscale-[0.2] group-hover:grayscale-0 transition-all duration-700"
              alt="Noivos"
            />
          </motion.div>

          <div className="space-y-6">
            <h1 className="text-5xl font-serif text-wedding-dark leading-tight">
              Ana & Bruno
            </h1>
            <p className="text-wedding-muted leading-relaxed font-light">
              Nossa história continua com você. A sua presença é o nosso maior presente, 
              mas se desejar nos presentear, criamos esta lista com carinho.
            </p>

            <div className="flex gap-8 pt-4">
              <div className="flex flex-col">
                <span className="text-2xl font-serif text-wedding-gold">142</span>
                <span className="text-[10px] uppercase tracking-widest text-wedding-muted font-bold">Dias</span>
              </div>
              <div className="flex flex-col">
                <span className="text-2xl font-serif text-wedding-gold">12</span>
                <span className="text-[10px] uppercase tracking-widest text-wedding-muted font-bold">Horas</span>
              </div>
              <div className="flex flex-col">
                <span className="text-2xl font-serif text-wedding-gold">54</span>
                <span className="text-[10px] uppercase tracking-widest text-wedding-muted font-bold">Min</span>
              </div>
            </div>
          </div>
        </aside>

        {/* Right Column: Gift Grid */}
        <div id="presentes" className="gift-grid-container flex flex-col">
          <div className="flex items-end justify-between border-b border-wedding-border pb-3 mb-8">
            <h2 className="text-2xl font-serif text-wedding-dark">Lista de Presentes</h2>
            <span className="text-[13px] text-wedding-muted">Mostrando {gifts.length} itens</span>
          </div>

          <GiftGrid 
            gifts={gifts} 
            onGiftSelect={setSelectedGift} 
          />
        </div>
      </main>

      {/* Checkout Modal */}
      <Modal 
        isOpen={!!selectedGift} 
        onClose={() => setSelectedGift(null)}
        title="Enviar Presente"
      >
        <div className="space-y-6">
          {selectedGift && (
            <div className="flex gap-4 p-4 bg-wedding-cream rounded-2xl border border-wedding-sage/10">
              <img 
                src={selectedGift.imageUrl} 
                className="w-20 h-20 object-cover rounded-xl"
                alt={selectedGift.title}
              />
              <div className="flex flex-col justify-center">
                <span className="text-xs uppercase tracking-widest text-wedding-sage font-bold">Resumo do Presente</span>
                <span className="text-lg font-serif">{selectedGift.title}</span>
                <span className="text-wedding-gold font-semibold">{formatCurrency(selectedGift.price)}</span>
              </div>
            </div>
          )}

          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-widest text-wedding-sage font-bold">Seu Nome</label>
              <input 
                type="text" 
                placeholder="Ex: Maria Oliveira"
                value={guestName}
                onChange={(e) => setGuestName(e.target.value)}
                className="w-full px-4 py-3 border border-gray-100 rounded-xl focus:ring-2 focus:ring-wedding-gold/20 focus:border-wedding-gold outline-none transition-all"
              />
            </div>

            <div className="space-y-2">
              <label className="text-xs uppercase tracking-widest text-wedding-sage font-bold flex items-center gap-2">
                <MessageSquare className="w-3 h-3" /> Deixe uma Mensagem
              </label>
              <textarea 
                rows={3}
                placeholder="Escreva algo carinhoso para o casal..."
                value={guestMessage}
                onChange={(e) => setGuestMessage(e.target.value)}
                className="w-full px-4 py-3 border border-gray-100 rounded-xl focus:ring-2 focus:ring-wedding-gold/20 focus:border-wedding-gold outline-none transition-all resize-none"
              />
            </div>
          </div>

          <div className="pt-4 space-y-3">
            <Button 
              onClick={handlePayment}
              disabled={!guestName || paying}
              className="w-full py-4 text-base tracking-widest uppercase font-bold"
            >
              {paying ? "Processando..." : "Confirmar e Ir para Pagamento"}
            </Button>
            <p className="text-[10px] text-center text-gray-400 uppercase tracking-widest">
              Garantia de transação segura • PIX ou Cartão
            </p>
          </div>
        </div>
      </Modal>

      <footer className="py-12 border-t border-wedding-sage/10 text-center">
        <p className="font-serif italic text-wedding-sage">Ana & Bruno • 12 de Setembro de 2026</p>
      </footer>
    </div>
  );
}
