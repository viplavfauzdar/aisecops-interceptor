/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        'decision-allow': 'var(--color-decision-allow)',
        'decision-block': 'var(--color-decision-block)',
        'decision-require-approval': 'var(--color-decision-require-approval)',
        'decision-dry-run': 'var(--color-decision-dry-run)',
      },
    },
  },
  plugins: [],
}
