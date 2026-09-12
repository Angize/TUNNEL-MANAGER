import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import './styles/tokens.css'
import './styles/base.css'
import './styles/shell.css'
import './styles/cards.css'
import './styles/forms.css'
import './styles/modal.css'
import './styles/toast.css'
import './styles/skeleton.css'
import './styles/select.css'
import './styles/traffic.css'
import './styles/readiness.css'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>
)
