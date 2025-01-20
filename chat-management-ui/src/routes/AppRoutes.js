import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import SecuritySystem from '../components/Authentication/SecuritySystem'; 
import Dashboard from '../pages/Dashboard'; // Import your component

const AppRoutes = () => (
  <Routes>
    {/* Redirect "/" to "/auth" */}
    <Route path="/" element={<Navigate to="/auth" />} />
    <Route path="/auth" element={<SecuritySystem />} />
    <Route path="/dashboard" element={<Dashboard />} />
    {/* Add other routes as needed */}
  </Routes>
);

export default AppRoutes;
