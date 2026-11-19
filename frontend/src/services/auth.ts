export interface User {
  id: string;
  name: string;
  email: string;
  token: string;
  createdAt: number;
}

const SESSION_KEY = 'sagearmor_session';
const GH_TOKEN_KEY = 'sagearmor_gh_token';

// In-memory fallback if sessionStorage is blocked
let inMemoryUser: User | null = null;
let inMemoryGhToken: string | null = null;

export const auth = {
  getCurrentUser(): User | null {
    if (inMemoryUser) return inMemoryUser;
    try {
      const stored = sessionStorage.getItem(SESSION_KEY);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch {
      // Ignore
    }
    return null;
  },

  isAuthenticated(): boolean {
    return Boolean(this.getCurrentUser());
  },

  login(email: string, password: string): { success: boolean; user?: User; error?: string } {
    if (!email || !password) {
      return { success: false, error: 'Email and password are required' };
    }
    if (password.length < 6) {
      return { success: false, error: 'Password must be at least 6 characters' };
    }

    const user: User = {
      id: `usr_${Math.random().toString(36).slice(2, 10)}`,
      name: email.split('@')[0] || 'Security Lead',
      email,
      token: `satk_${Math.random().toString(36).slice(2)}`,
      createdAt: Date.now(),
    };

    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(user));
    } catch {
      inMemoryUser = user;
    }
    return { success: true, user };
  },

  signup(name: string, email: string, password: string): { success: boolean; user?: User; error?: string } {
    if (!name || !email || !password) {
      return { success: false, error: 'All fields are required' };
    }
    if (password.length < 6) {
      return { success: false, error: 'Password must be at least 6 characters' };
    }

    const user: User = {
      id: `usr_${Math.random().toString(36).slice(2, 10)}`,
      name,
      email,
      token: `satk_${Math.random().toString(36).slice(2)}`,
      createdAt: Date.now(),
    };

    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(user));
    } catch {
      inMemoryUser = user;
    }
    return { success: true, user };
  },

  logout(): void {
    inMemoryUser = null;
    inMemoryGhToken = null;
    try {
      sessionStorage.removeItem(SESSION_KEY);
      sessionStorage.removeItem(GH_TOKEN_KEY);
    } catch {
      // Ignore
    }
  },

  getGitHubToken(): string | null {
    if (inMemoryGhToken) return inMemoryGhToken;
    try {
      return sessionStorage.getItem(GH_TOKEN_KEY);
    } catch {
      return null;
    }
  },

  setGitHubToken(token: string | null): void {
    inMemoryGhToken = token;
    try {
      if (token) {
        sessionStorage.setItem(GH_TOKEN_KEY, token);
      } else {
        sessionStorage.removeItem(GH_TOKEN_KEY);
      }
    } catch {
      // Ignore
    }
  },
};
