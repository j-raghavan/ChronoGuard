import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

// Set default tenant ID for demo purposes
// In production, this would come from authentication
if (!localStorage.getItem('tenantId')) {
  localStorage.setItem('tenantId', '550e8400-e29b-41d4-a716-446655440000');
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
