# 💍 Wedding Gift List

A modern, elegant, and interactive wedding gift list application built with **React 19**, **Firebase**, and **Tailwind CSS**.

![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?style=for-the-badge&logo=typescript)
![Firebase](https://img.shields.io/badge/Firebase-12-FFCA28?style=for-the-badge&logo=firebase)
![Tailwind](https://img.shields.io/badge/Tailwind_CSS-4-06B6D4?style=for-the-badge&logo=tailwind-css)
![Vite](https://img.shields.io/badge/Vite-6-646CFF?style=for-the-badge&logo=vite)

## ✨ Features

- 🎁 **Interactive Gift Grid**: Beautifully displayed gift options with real-time status updates.
- 💳 **Payment Integration**: Seamless contribution flow (ready for Mercado Pago/Stripe).
- 💬 **Guest Messages**: Allow guests to leave heartwarming messages with their gifts.
- 📱 **Fully Responsive**: Optimized for desktop, tablet, and mobile devices.
- ⚡ **Real-time Sync**: Powered by Firestore for instant updates across all users.
- 🎨 **Modern UI**: Smooth animations using Framer Motion and elegant styling with Tailwind CSS.

## 🛠️ Tech Stack

- **Frontend**: React 19 (Hooks, Context API)
- **Styling**: Tailwind CSS 4, Framer Motion (animations), Lucide React (icons)
- **Backend/Database**: Firebase (Firestore)
- **Server**: Express (Node.js) with tsx for development
- **Build Tool**: Vite

## 🚀 Getting Started

### Prerequisites

- Node.js (v18 or higher)
- npm or yarn
- A Firebase project

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/gcvilela/wed_list.git
   cd wed_list
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Environment Setup:**
   Create a `.env` file in the root and add your Firebase credentials:
   ```env
   VITE_FIREBASE_API_KEY=your_api_key
   VITE_FIREBASE_AUTH_DOMAIN=your_auth_domain
   VITE_FIREBASE_PROJECT_ID=your_project_id
   VITE_FIREBASE_STORAGE_BUCKET=your_storage_bucket
   VITE_FIREBASE_MESSAGING_SENDER_ID=your_messaging_sender_id
   VITE_FIREBASE_APP_ID=your_app_id
   ```

4. **Run development server:**
   ```bash
   npm run dev
   ```

## 📁 Project Structure

```text
src/
├── components/     # Reusable UI components
│   ├── ui/         # Base UI elements (Button, Modal)
│   ├── GiftCard    # Individual gift item
│   └── GiftGrid    # Main gift listing
├── lib/            # Utilities and helper functions
├── firebase.ts     # Firebase configuration
├── types.ts        # TypeScript interfaces
└── App.tsx         # Main application logic
```

## 🤝 Contributing

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

Distributed under the Apache-2.0 License. See `LICENSE` for more information.

---
Built with ❤️ for a special day.
