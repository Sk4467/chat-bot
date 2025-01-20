import React from 'react';
import { createRoot } from 'react-dom/client'; // Import createRoot
import App from './App'; // Main App component
import './index.css'; // Global styles

// Get the root element
const rootElement = document.getElementById('root');
const root = createRoot(rootElement); // Create a root using createRoot

// Render the App component
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

