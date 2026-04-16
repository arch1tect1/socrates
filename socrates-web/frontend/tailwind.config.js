/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        surface: {
          primary: "var(--bg-primary)",
          card: "var(--bg-card)",
          "card-hover": "var(--bg-card-hover)",
        },
        border: {
          DEFAULT: "var(--border)",
          active: "var(--border-active)",
        },
        content: {
          primary: "var(--text-primary)",
          secondary: "var(--text-secondary)",
          muted: "var(--text-muted)",
        },
        accent: {
          cyan: "#22d3ee",
          green: "#22c55e",
          orange: "#f59e0b",
          red: "#ef4444",
          purple: "#a78bfa",
          yellow: "#fbbf24",
        },
      },
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "Source Code Pro",
          "monospace",
        ],
        display: ["Space Grotesk", "Inter", "sans-serif"],
      },
    },
  },
  plugins: [],
};
