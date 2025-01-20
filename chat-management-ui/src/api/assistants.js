// import axios from 'axios';

// const API_BASE_URL = 'http://localhost:8000'; // Replace with your backend URL

// export const fetchAssistants = async () => {
//   const token = localStorage.getItem('token'); // Retrieve JWT token
//   const response = await axios.get(`${API_BASE_URL}/assistants`, {
//     headers: { Authorization: `Bearer ${token}` },
//   });
//   return response.data;
// };

import axios from 'axios';

const API_BASE_URL = 'http://127.0.0.1:8000'; // Use consistent base URL

export const fetchAssistants = async () => {
  const token = localStorage.getItem('token'); // Retrieve JWT token
  const response = await axios.get(`${API_BASE_URL}/assistants/assistants`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  console.log(`${API_BASE_URL}/assistants/assistants`);
  return response.data;
};