import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

export default function ThemeToggle() {
  const [dark, setDark] = useState(() => {
    if (typeof window === "undefined") return true;
    const stored = localStorage.getItem("socrates-theme");
    return stored ? stored === "dark" : true;
  });

  useEffect(() => {
    const root = document.documentElement;
    if (dark) {
      root.classList.add("dark");
    } else {
      root.classList.remove("dark");
    }
    localStorage.setItem("socrates-theme", dark ? "dark" : "light");
  }, [dark]);

  return (
    <button
      type="button"
      onClick={() => setDark((d) => !d)}
      className="relative flex items-center justify-center w-10 h-10 rounded-lg border transition-all duration-200 hover:scale-105"
      style={{
        background: "var(--bg-card)",
        borderColor: "var(--border)",
      }}
      aria-label="Toggle theme"
    >
      {dark ? (
        <Sun size={18} className="text-accent-yellow" />
      ) : (
        <Moon size={18} className="text-accent-purple" />
      )}
    </button>
  );
}
