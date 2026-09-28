import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { ToastProvider } from './components/controls';
import './index.css';
import { applyAppearance, applyCachedAppearance, type Appearance } from './theme';

// The saved theme applies before the first paint, then the portal's copy.
applyCachedAppearance();
fetch('/api/appearance', { credentials: 'same-origin' })
  .then((r) => (r.ok ? r.json() : null))
  .then((d: { appearance: Appearance } | null) => d && applyAppearance(d.appearance))
  .catch(() => {});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <App />
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>,
);
