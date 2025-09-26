// expo-sanctum-auth/index.js
import React, { createContext, useContext, useState, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';
import { useRouter, useSegments } from 'expo-router';

// Create auth context
const SanctumAuthContext = createContext(null);

// Storage keys
const TOKEN_KEY = 'sanctum_auth_token';
const USER_KEY = 'sanctum_auth_user';

export const SanctumProvider = ({
                                    children,
                                    apiBaseUrl,
                                    loginEndpoint = '/login',
                                    registerEndpoint = '/register',
                                    userEndpoint = '/user',
                                    logoutEndpoint = '/logout',
                                    csrfEndpoint = '/sanctum/csrf-cookie',
                                    redirectIfAuthenticated = '/(app)',
                                    redirectIfUnauthenticated = '/(auth)',
                                    onLogin = () => {},
                                    onLogout = () => {},
                                    onRegister = () => {},
                                }) => {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const router = useRouter();
    const segments = useSegments();

    // Create API client
    const api = axios.create({
        baseURL: apiBaseUrl,
        withCredentials: true,
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
    });

    // Add token to requests
    api.interceptors.request.use(config => {
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    });

    // Load stored session
    useEffect(() => {
        const loadSession = async () => {
            try {
                const storedToken = await AsyncStorage.getItem(TOKEN_KEY);
                const storedUser = await AsyncStorage.getItem(USER_KEY);

                if (storedToken && storedUser) {
                    setToken(storedToken);
                    setUser(JSON.parse(storedUser));
                    api.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`;
                }
            } catch (e) {
                console.error('Failed to load auth session', e);
            } finally {
                setLoading(false);
            }
        };

        loadSession();
    }, []);

    // Handle routing based on auth state
    useEffect(() => {
        if (loading) return;

        const inAuthGroup = segments[0] === '(auth)';
        const inAppGroup = segments[0] === '(app)';

        if (user && inAuthGroup) {
            router.replace(redirectIfAuthenticated);
        } else if (!user && inAppGroup) {
            router.replace(redirectIfUnauthenticated);
        }
    }, [user, loading, segments]);

    // Save session data
    const saveSession = async (newToken, newUser) => {
        try {
            await AsyncStorage.setItem(TOKEN_KEY, newToken);
            await AsyncStorage.setItem(USER_KEY, JSON.stringify(newUser));
        } catch (e) {
            console.error('Failed to save auth session', e);
        }
    };

    // Clear session data
    const clearSession = async () => {
        try {
            await AsyncStorage.removeItem(TOKEN_KEY);
            await AsyncStorage.removeItem(USER_KEY);
        } catch (e) {
            console.error('Failed to clear auth session', e);
        }
    };

    // Get CSRF cookie
    const getCsrfCookie = async () => {
        try {
            await api.get(csrfEndpoint);
        } catch (e) {
            console.error('Failed to get CSRF cookie', e);
        }
    };

    // Login function
    const login = async (email, password) => {
        try {
            setError(null);
            setLoading(true);

            // Get CSRF cookie if needed
            await getCsrfCookie();

            const response = await api.post(loginEndpoint, { email, password });
            const { user: userData, token: authToken } = response.data;

            setUser(userData);
            setToken(authToken);
            api.defaults.headers.common['Authorization'] = `Bearer ${authToken}`;

            await saveSession(authToken, userData);
            onLogin(userData);

            return userData;
        } catch (e) {
            setError(e.response?.data?.message || 'Login failed');
            throw e;
        } finally {
            setLoading(false);
        }
    };

    // Register function
    const register = async (userData) => {
        try {
            setError(null);
            setLoading(true);

            // Get CSRF cookie if needed
            await getCsrfCookie();

            const response = await api.post(registerEndpoint, userData);
            const { user: newUser, token: authToken } = response.data;

            setUser(newUser);
            setToken(authToken);
            api.defaults.headers.common['Authorization'] = `Bearer ${authToken}`;

            await saveSession(authToken, newUser);
            onRegister(newUser);

            return newUser;
        } catch (e) {
            setError(e.response?.data?.message || 'Registration failed');
            throw e;
        } finally {
            setLoading(false);
        }
    };

    // Logout function
    const logout = async () => {
        try {
            setLoading(true);

            // Call logout endpoint if token exists
            if (token) {
                await api.post(logoutEndpoint);
            }

            setUser(null);
            setToken(null);
            delete api.defaults.headers.common['Authorization'];

            await clearSession();
            onLogout();
        } catch (e) {
            console.error('Logout failed', e);
            // Still clear local session even if API call fails
            setUser(null);
            setToken(null);
            await clearSession();
        } finally {
            setLoading(false);
        }
    };

    // Refresh user data
    const refreshUser = async () => {
        try {
            if (!token) return null;

            const response = await api.get(userEndpoint);
            const userData = response.data;

            setUser(userData);
            await AsyncStorage.setItem(USER_KEY, JSON.stringify(userData));

            return userData;
        } catch (e) {
            console.error('Failed to refresh user data', e);

            // If unauthorized, clear session
            if (e.response?.status === 401) {
                logout();
            }

            return null;
        }
    };

    const value = {
        user,
        token,
        loading,
        error,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        refreshUser,
        api,
    };

    return (
        <SanctumAuthContext.Provider value={value}>
            {children}
        </SanctumAuthContext.Provider>
    );
};

// Custom hook to use auth context
export const useSanctum = () => {
    const context = useContext(SanctumAuthContext);
    if (!context) {
        throw new Error('useSanctum must be used within a SanctumProvider');
    }
    return context;
};

// Higher-order component to protect routes
export const withSanctumAuth = (Component) => {
    return (props) => {
        const { isAuthenticated, loading } = useSanctum();
        const router = useRouter();

        useEffect(() => {
            if (!loading && !isAuthenticated) {
                router.replace('/(auth)');
            }
        }, [isAuthenticated, loading, router]);

        if (loading) {
            return null; // Or your loading component
        }

        return isAuthenticated ? <Component {...props} /> : null;
    };
};