// // src/api/auth.js

// const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api/v1';

// export const authAPI = {
//   login: async (username, password) => {
//     try {
//       const response = await fetch(`${API_BASE_URL}/auth/login`, {
//         method: 'POST',
//         headers: {
//           'Content-Type': 'application/json',
//         },
//         body: JSON.stringify({ username, password }),
//       });
      
//       if (!response.ok) {
//         throw new Error('Login failed');
//       }
      
//       return await response.json();
//     } catch (error) {
//       throw error;
//     }
//   },

//   register: async (username, password, tenant_id) => {
//     try {
//       const response = await fetch(`${API_BASE_URL}/auth/register`, {
//         method: 'POST',
//         headers: {
//           'Content-Type': 'application/json',
//         },
//         body: JSON.stringify({ username, password, tenant_id }),
//       });
      
//       if (!response.ok) {
//         throw new Error('Registration failed');
//       }
      
//       return await response.json();
//     } catch (error) {
//       throw error;
//     }
//   },
// };