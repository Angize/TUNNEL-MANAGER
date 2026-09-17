import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
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
import './styles/acts.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>
)
