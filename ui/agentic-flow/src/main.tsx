import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import './styles/index.css'
import { initializeConsole } from './utils/consoleInit'

// Initialize console with branding and developer tools
initializeConsole()

// Initialize app with strict mode for better development experience
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)