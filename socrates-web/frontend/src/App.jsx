import { useState } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Analytics } from "@vercel/analytics/react";
import Header from "./components/Header";
import HomePage from "./pages/HomePage";
import AlertsPage from "./pages/AlertsPage";
import AlertDetailPage from "./pages/AlertDetailPage";

export default function App() {
  const [homeKey, setHomeKey] = useState(0);
  const handleLogoReset = () => setHomeKey((k) => k + 1);

  return (
    <BrowserRouter>
      <div
        className="min-h-screen flex flex-col w-full"
        style={{ background: "var(--bg-primary)" }}
      >
        <Header onReset={handleLogoReset} />

        <Routes>
          <Route path="/" element={<HomePage resetKey={homeKey} />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/alerts/:id" element={<AlertDetailPage />} />
        </Routes>

        <footer
          className="shrink-0 mt-auto text-center py-6 text-xs w-full"
          style={{
            color: "var(--text-muted)",
            borderTop: "1px solid var(--border)",
            background: "color-mix(in srgb, var(--bg-primary) 92%, transparent)",
          }}
        >
          SOCrates v1.0 - AI-Powered IOC Triage Platform
        </footer>

        <Analytics />
      </div>
    </BrowserRouter>
  );
}
