import { useState } from 'react';
import { Shield, Mail, Lock, User, Check, ArrowRight } from 'lucide-react';
import { PageTransition } from '../components/shared/PageTransition';
import { motion, AnimatePresence } from 'motion/react';
import { Link } from 'react-router-dom';

export default function AuthPage({ mode = 'signup' }: { mode?: 'login' | 'signup' }) {
  const [isLogin, setIsLogin] = useState(mode === 'login');

  const features = [
    'Real-time vulnerability scanning',
    'AI-powered security analysis',
    'Automated fix suggestions',
    'GitHub/GitLab integration',
  ];

  return (
    <PageTransition>
      <div className="min-h-screen bg-[#0A0F1C] pt-28 pb-20 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            {/* Left Side - Branding & Features */}
            <div className="hidden lg:block">
              <Link to="/" className="flex items-center gap-3 mb-8 group">
                <div className="relative">
                  <Shield className="w-12 h-12 text-cyan-400 group-hover:scale-110 transition-transform" />
                  <div className="absolute inset-0 bg-cyan-400/20 blur-xl" />
                </div>
                <span className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                  SageArmor
                </span>
              </Link>

              <h1 className="text-5xl font-bold text-white mb-6 leading-tight" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                {isLogin ? 'Welcome Back To Security' : 'Start Securing Your Code Today'}
              </h1>
              <p className="text-xl text-gray-400 mb-8 max-w-md">
                Join thousands of developers using AI-powered security analysis to protect their applications.
              </p>

              {/* Features List */}
              <div className="space-y-4">
                {features.map((feature, index) => (
                  <motion.div 
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    key={index} 
                    className="flex items-center gap-3 group"
                  >
                    <div className="p-1 rounded-full bg-cyan-500/20 border border-cyan-500/30 group-hover:bg-cyan-500/30 transition-all">
                      <Check className="w-4 h-4 text-cyan-400" />
                    </div>
                    <span className="text-gray-300 group-hover:text-white transition-colors">{feature}</span>
                  </motion.div>
                ))}
              </div>

              <div className="grid grid-cols-3 gap-6 mt-12 pt-12 border-t border-white/10">
                <div>
                  <p className="text-3xl font-bold text-white mb-1">10k+</p>
                  <p className="text-sm text-gray-400">Active Users</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-white mb-1">1M+</p>
                  <p className="text-sm text-gray-400">Scans Done</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-white mb-1">99.8%</p>
                  <p className="text-sm text-gray-400">Accuracy</p>
                </div>
              </div>
            </div>

            {/* Right Side - Form */}
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 blur-3xl -z-10" />

              <div className="relative backdrop-blur-xl bg-white/5 border border-white/10 rounded-2xl p-8 shadow-2xl">
                <div className="text-center mb-8">
                  <div className="inline-flex items-center gap-2 bg-blue-500/10 border border-blue-500/30 rounded-full px-4 py-2 mb-4">
                    <Shield className="w-4 h-4 text-blue-400" />
                    <span className="text-sm text-blue-300">Enterprise Grade Security</span>
                  </div>
                  <h2 className="text-3xl font-bold text-white mb-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                    {isLogin ? 'Sign In' : 'Create Account'}
                  </h2>
                  <p className="text-gray-400">
                    {isLogin ? 'Access your security dashboard' : 'Free 14-day trial, no card required'}
                  </p>
                </div>

                {/* Social Login */}
                <div className="grid grid-cols-1 gap-4 mb-6">
                  <motion.button
                    whileHover={{ scale: 1.02, y: -2 }}
                    whileTap={{ scale: 0.98 }}
                    className="flex items-center justify-center gap-2 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-cyan-400/30 text-white px-4 py-3 rounded-lg transition-all"
                  >
                    <svg className="w-5 h-5 text-gray-400" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.89 1.53 2.34 1.09 2.91.83.09-.65.35-1.09.64-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.1.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.58 9.58 0 0 1 5 0c1.91-1.3 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.6 1.03 2.69 0 3.84-2.34 4.69-4.57 4.94.36.31.68.92.68 1.85v2.75c0 .27.18.58.69.48A10 10 0 0 0 12 2Z"/></svg>
                    <span>Continue with GitHub</span>
                  </motion.button>
                </div>

                <div className="relative mb-6">
                  <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-white/10" /></div>
                  <div className="relative flex justify-center text-sm"><span className="px-4 bg-[#0A0F1C] text-gray-400">Or use email</span></div>
                </div>

                <form onSubmit={(e) => { e.preventDefault(); window.location.href='/scanner'; }} className="space-y-5">
                  <AnimatePresence mode="wait">
                    {!isLogin && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                      >
                        <label className="block text-sm font-medium text-gray-300 mb-2">Full Name</label>
                        <div className="relative">
                          <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                          <input
                            type="text"
                            required
                            className="w-full bg-white/5 border border-white/10 rounded-lg px-12 py-3 text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/20 transition-all"
                            placeholder="John Doe"
                          />
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Email Address</label>
                    <div className="relative group">
                      <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400 group-focus-within:text-cyan-400 transition-colors" />
                      <input
                        type="email"
                        required
                        className="w-full bg-white/5 border border-white/10 rounded-lg px-12 py-3 text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/20 transition-all"
                        placeholder="john@example.com"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
                    <div className="relative group">
                      <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400 group-focus-within:text-cyan-400 transition-colors" />
                      <input
                        type="password"
                        required
                        className="w-full bg-white/5 border border-white/10 rounded-lg px-12 py-3 text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/20 transition-all"
                        placeholder="••••••••"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    className="w-full bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white font-medium px-6 py-4 rounded-lg transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2 group"
                  >
                    <span>{isLogin ? 'Sign In' : 'Create Account'}</span>
                    <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                  </button>
                </form>

                <p className="text-center text-gray-400 mt-6 text-sm">
                  {isLogin ? "Don't have an account?" : "Already have an account?"}{' '}
                  <button 
                    onClick={() => setIsLogin(!isLogin)}
                    className="text-cyan-400 hover:text-cyan-300 font-medium ml-1"
                  >
                    {isLogin ? 'Sign Up' : 'Sign In'}
                  </button>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </PageTransition>
  );
}
