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
        background: {
          DEFAULT: '#060B17',
          deep: '#040711',
          card: '#0D1527',
          cardHover: '#111C35',
          border: 'rgba(56, 189, 248, 0.12)',
          borderGlow: 'rgba(0, 240, 255, 0.25)',
        },
        navy: {
          950: '#060B17',
          900: '#0A1124',
          850: '#0D152B',
          800: '#111C35',
          700: '#1A294C',
          600: '#263B66',
        },
        cyan: {
          accent: '#00F0FF',
          glow: 'rgba(0, 240, 255, 0.4)',
        },
        electric: {
          blue: '#2563EB',
          sky: '#38BDF8',
          indigo: '#6366F1',
        },
        status: {
          verified: '#10B981',
          'verified-glow': 'rgba(16, 185, 129, 0.25)',
          edited: '#EF4444',
          'edited-glow': 'rgba(239, 68, 68, 0.25)',
          unknown: '#F59E0B',
          'unknown-glow': 'rgba(245, 158, 11, 0.25)',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px -3px rgba(0, 240, 255, 0.25)',
        'glow-blue': '0 0 20px -3px rgba(37, 99, 235, 0.3)',
        'glow-green': '0 0 20px -3px rgba(16, 185, 129, 0.3)',
        'glow-red': '0 0 20px -3px rgba(239, 68, 68, 0.3)',
        'glow-amber': '0 0 20px -3px rgba(245, 158, 11, 0.3)',
        'card-dark': '0 10px 30px -10px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.05)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan': 'scan 2.5s ease-in-out infinite',
      },
      keyframes: {
        scan: {
          '0%, 100%': { transform: 'translateY(0%)' },
          '50%': { transform: 'translateY(100%)' },
        }
      }
    },
  },
  plugins: [],
}

