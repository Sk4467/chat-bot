import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom'; // For navigation after login

// Login Form Component
const LoginForm = ({ formData, handleChange, handleLogin, error }) => (
  <form onSubmit={handleLogin} className="space-y-4">
    <div>
      <label className="text-lg font-medium mb-2 block">Username</label>
      <input
        type="text"
        name="username"
        value={formData.username}
        onChange={handleChange}
        placeholder="Enter username"
        className="w-full p-2 rounded border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
        required
      />
    </div>
    <div>
      <label className="text-lg font-medium mb-2 block">Password</label>
      <input
        type="password"
        name="password"
        value={formData.password}
        onChange={handleChange}
        placeholder="Enter password"
        className="w-full p-2 rounded border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
        required
      />
    </div>
    {error && <p className="text-red-600">{error}</p>}
    <button
      type="submit"
      className="w-full p-2 bg-slate-900 text-white rounded hover:bg-slate-800 transition-colors"
    >
      Sign In
    </button>
  </form>
);

// Register Form Component
const RegisterForm = ({ formData, handleChange, handleRegister, error }) => (
  <form onSubmit={handleRegister} className="space-y-4">
    <div>
      <label className="text-lg font-medium mb-2 block">Username</label>
      <input
        type="text"
        name="username"
        value={formData.username}
        onChange={handleChange}
        placeholder="Choose username"
        className="w-full p-2 rounded border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
        required
      />
    </div>
    <div>
      <label className="text-lg font-medium mb-2 block">Tenant ID</label>
      <input
        type="text"
        name="tenantId"
        value={formData.tenantId}
        onChange={handleChange}
        placeholder="Enter tenant ID"
        className="w-full p-2 rounded border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
        required
      />
    </div>
    <div>
      <label className="text-lg font-medium mb-2 block">Password</label>
      <input
        type="password"
        name="password"
        value={formData.password}
        onChange={handleChange}
        placeholder="Choose password"
        className="w-full p-2 rounded border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
        required
      />
    </div>
    {error && <p className="text-red-600">{error}</p>}
    <button
      type="submit"
      className="w-full p-2 bg-slate-900 text-white rounded hover:bg-slate-800 transition-colors"
    >
      Register
    </button>
  </form>
);

// Main Component
const SecuritySystem = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    username: '',
    tenantId: '',
    password: '',
  });
  const [error, setError] = useState(null);
  const navigate = useNavigate(); // React Router hook for navigation

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      const response = await axios.post('http://localhost:8000/auth/login', {
        user_name: formData.username,
        password: formData.password,
      });
      localStorage.setItem('token', response.data.token); // Save JWT token
      alert('Login successful!');
      navigate('/dashboard'); // Navigate to Dashboard
    } catch (err) {
      setError('Invalid login credentials. Please try again.');
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      await axios.post('http://localhost:8000/auth/register', {
        user_name: formData.username,
        tenant_id: formData.tenantId,
        password: formData.password,
      });
      alert('Registration successful! You can now log in.');
      setIsLogin(true); // Switch to Login view
    } catch (err) {
      setError('Registration failed. Try again with different credentials.');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 p-4">
      <div className="w-full max-w-md bg-white rounded-lg shadow-lg p-6">
        <h1 className="text-2xl font-bold text-center mb-6">Security System</h1>

        <div className="mb-6">
          <div className="grid grid-cols-2 gap-1 bg-slate-100 p-1 rounded">
            <button
              className={`p-2 rounded text-center transition-colors ${
                isLogin ? 'bg-white shadow' : 'hover:bg-slate-200'
              }`}
              onClick={() => setIsLogin(true)}
            >
              Login
            </button>
            <button
              className={`p-2 rounded text-center transition-colors ${
                !isLogin ? 'bg-white shadow' : 'hover:bg-slate-200'
              }`}
              onClick={() => setIsLogin(false)}
            >
              Register
            </button>
          </div>
        </div>

        {isLogin ? (
          <LoginForm
            formData={formData}
            handleChange={handleChange}
            handleLogin={handleLogin}
            error={error}
          />
        ) : (
          <RegisterForm
            formData={formData}
            handleChange={handleChange}
            handleRegister={handleRegister}
            error={error}
          />
        )}
      </div>
    </div>
  );
};

export default SecuritySystem;
