import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // For now, we'll use a mock token for development
    // In production, this would integrate with Keycloak
    if (!token) {
      const mockToken = 'mock-jwt-token-for-development';
      setToken(mockToken);
      localStorage.setItem('token', mockToken);
      setUser({
        id: 'user-1',
        name: 'Admin User',
        email: 'admin@secdash.local',
        roles: ['admin']
      });
    }
    setLoading(false);
  }, [token]);

  const login = async (credentials) => {
    // Mock login for development
    // In production, this would authenticate with Keycloak
    try {
      const mockToken = 'mock-jwt-token-for-development';
      setToken(mockToken);
      localStorage.setItem('token', mockToken);
      setUser({
        id: 'user-1',
        name: 'Admin User',
        email: 'admin@secdash.local',
        roles: ['admin']
      });
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
  };

  const value = {
    token,
    user,
    login,
    logout,
    loading,
    isAuthenticated: !!token
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
