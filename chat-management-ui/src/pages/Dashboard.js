import React, { useEffect, useState } from 'react';
import { fetchAssistants } from '../api/assistants';
import axios from 'axios';

const API_BASE_URL = 'http://127.0.0.1:8000';

const Dashboard = () => {
  const [assistants, setAssistants] = useState([]);
  const [error, setError] = useState(null);
  const [chatSessions, setChatSessions] = useState({});
  const [activeAssistant, setActiveAssistant] = useState(null);
  const [activeSession, setActiveSession] = useState(null);
  const [chatHistory, setChatHistory] = useState([]);
  const [newMessage, setNewMessage] = useState('');

  useEffect(() => {
    const getAssistants = async () => {
      try {
        const data = await fetchAssistants();
        setAssistants(data);
      } catch (err) {
        console.error('Failed to fetch assistants:', err);
        setError('Failed to load assistants. Please try again later.');
      }
    };

    getAssistants();
  }, []);

  const fetchChatSessions = async (assistantId) => {
    const token = localStorage.getItem('token');
    try {
      const response = await axios.get(
        `${API_BASE_URL}/assistants/${assistantId}/chat_sessions`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setChatSessions((prev) => ({
        ...prev,
        [assistantId]: response.data,
      }));
    } catch (err) {
      console.error('Failed to fetch chat sessions:', err);
      setError('Failed to load chat sessions. Please try again later.');
    }
  };

  const startNewChatSession = async (assistantId) => {
    const token = localStorage.getItem('token');
    try {
      const response = await axios.post(
        `${API_BASE_URL}/assistants/${assistantId}/chat_sessions`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const newSession = response.data;

      setChatSessions((prev) => ({
        ...prev,
        [assistantId]: [...(prev[assistantId] || []), newSession],
      }));
      setActiveSession(newSession.session_id);
      setChatHistory([]); // Clear chat history for a new session
    } catch (err) {
      console.error('Failed to start a new chat session:', err);
      setError('Failed to start a new chat session. Please try again later.');
    }
  };

  const fetchChatHistory = async (chatSessionId) => {
    const token = localStorage.getItem('token');
    try {
      const response = await axios.get(
        `${API_BASE_URL}/chat_sessions/${chatSessionId}/history`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setChatHistory(response.data);
      setActiveSession(chatSessionId);
    } catch (err) {
      console.error('Failed to fetch chat history:', err);
      setError('Failed to load chat history. Please try again later.');
    }
  };

  const sendMessage = async () => {
    if (!newMessage.trim()) return; // Prevent empty messages
    const token = localStorage.getItem('token');
  
    try {
      // Add user message to the chat history immediately
      const userMessage = {
        message_id: `user-${Date.now()}`, // Temporary ID for UI
        sender: 'user',
        content: newMessage,
        timestamp: new Date().toISOString(),
      };
      setChatHistory((prev) => [...prev, userMessage]);
  
      // Send the user query to the backend
      const response = await axios.post(
        `${API_BASE_URL}/chat_sessions/${activeSession}/query`,
        { query: newMessage },
        { headers: { Authorization: `Bearer ${token}` } }
      );
  
      // Extract the response content
      const assistantResponseContent =
        response.data.response || 'No response received.';
  
      // Add assistant's response to the chat history
      const assistantMessage = {
        message_id: `assistant-${Date.now()}`, // Temporary ID for UI
        sender: 'assistant',
        content: assistantResponseContent,
        timestamp: new Date().toISOString(),
      };
      setChatHistory((prev) => [...prev, assistantMessage]);
  
      // Clear the input box
      setNewMessage('');
    } catch (err) {
      console.error('Failed to send the message:', err);
      setError('Failed to send the message. Please try again later.');
  
      // Add a fallback message if the backend fails
      const fallbackMessage = {
        message_id: `assistant-${Date.now()}`,
        sender: 'assistant',
        content: 'Failed to fetch response from the server.',
        timestamp: new Date().toISOString(),
      };
      setChatHistory((prev) => [...prev, fallbackMessage]);
    }
  };
  
  

  return (
    <div className="flex h-screen">
      <div className="w-1/4 bg-gray-100 p-4">
        <h2 className="text-lg font-bold mb-4">Assistants</h2>
        {error && <p className="text-red-600">{error}</p>}
        {assistants.length > 0 ? (
          <div className="space-y-4">
            {assistants.map((assistant) => (
              <div key={assistant.assistant_id} className="space-y-2">
                <div
                  className="flex items-center justify-between p-2 bg-white rounded-lg shadow cursor-pointer"
                  onClick={() => {
                    setActiveAssistant(assistant.assistant_id);
                    fetchChatSessions(assistant.assistant_id);
                  }}
                >
                  <span className="text-gray-600">{assistant.assistant_name}</span>
                </div>
                {activeAssistant === assistant.assistant_id &&
                  chatSessions[assistant.assistant_id] && (
                    <div className="ml-4 space-y-2">
                      {chatSessions[assistant.assistant_id].map((session) => (
                        <div
                          key={session.session_id}
                          className="p-2 bg-gray-50 rounded-lg shadow cursor-pointer"
                          onClick={() => fetchChatHistory(session.session_id)}
                        >
                          <span className="text-sm text-gray-500">
                            Session ID: {session.session_id}
                          </span>
                          <br />
                          <span className="text-xs text-gray-400">
                            Created At: {session.created_at}
                          </span>
                        </div>
                      ))}
                      <button
                        onClick={() => startNewChatSession(assistant.assistant_id)}
                        className="p-2 bg-blue-500 text-white rounded hover:bg-blue-600 mt-2"
                      >
                        Start New Chat Session
                      </button>
                    </div>
                  )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-600">No assistants available.</p>
        )}
      </div>

      <div className="w-3/4 flex flex-col">
        <div className="flex-1 p-4 overflow-y-auto bg-white">
          {activeSession ? (
            chatHistory.map((message, index) => (
              <div
                key={`${message.message_id}-${index}`}
                className={`p-2 rounded-lg mb-2 ${
                  message.sender === 'user'
                    ? 'bg-blue-100 self-end'
                    : 'bg-gray-100 self-start'
                }`}
              >
                <p className="text-sm">{message.content}</p>
                <p className="text-xs text-gray-400">{message.timestamp}</p>
              </div>
            ))
          ) : (
            <p className="text-gray-600 text-center mt-10">
              Select or start a chat session to begin messaging.
            </p>
          )}
        </div>
        {activeSession && (
          <div className="p-4 flex items-center bg-gray-50">
            <input
              type="text"
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              placeholder="Type your message..."
              className="flex-1 p-2 rounded border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={sendMessage}
              className="ml-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
            >
              Send
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
