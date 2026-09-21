/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        obsidian: {
          950: '#07090E',
          900: '#0B0F17',
          850: '#101622',
          800: '#161F30',
          700: '#233049',
          600: '#344563',
        },
        cyber: {
          cyan: '#38bdf8',
          crimson: '#ef4444',
          amber: '#f59e0b',
          emerald: '#10b981',
          violet: '#8b5cf6'
        }
      },
      fontFamily: {
        sans: ['Outfit', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      }
    },
  },
  plugins: [],
}
