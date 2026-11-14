import { Routes, Route, useLocation } from 'react-router-dom';
import { AnimatePresence } from 'motion/react';
import { useEffect, useState } from 'react';

// Components
import { Navigation } from './components/shared/Navigation';
import LandingPage from './pages/LandingPage';
import AuthPage from './pages/AuthPage';
import ScannerPage from './pages/ScannerPage';

/* ── Global Animated Background ── */
function AnimatedBackground() {
  const [mouse, setMouse] = useState({ x: 0, y: 0 });
  
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      setMouse({ x: e.clientX, y: e.clientY });
    };
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  return (
    <div className="fixed inset-0 -z-10 overflow-hidden pointer-events-none bg-[#0A0F1C]">
      {/* Radial Glow follow mouse */}
      <div 
        className="absolute w-[800px] h-[800px] rounded-full opacity-20 blur-[120px] transition-all duration-700 ease-out -translate-x-1/2 -translate-y-1/2"
        style={{
          left: mouse.x,
          top: mouse.y,
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.3) 0%, rgba(6, 182, 212, 0.1) 50%, transparent 100%)'
        }}
      />
      
      {/* Static Background Accents */}
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-[150px]" />
      <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-purple-600/10 rounded-full blur-[150px]" />
      
      {/* Grid Pattern */}
      <div className="absolute inset-0 opacity-[0.03]">
        <div className="w-full h-full" style={{
          backgroundImage: `linear-gradient(to right, rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.1) 1px, transparent 1px)`,
          backgroundSize: '40px 40px',
        }} />
      </div>
    </div>
  );
}

function App() {
  const location = useLocation();

  return (
    <div className="min-h-screen text-[#E5E7EB] font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      <AnimatedBackground />
      <Navigation />
      
      <AnimatePresence mode="wait">
        <Routes location={location} key={location.pathname}>
          <Route path="/" element={<LandingPage />} />
          <Route path="/signup" element={<AuthPage mode="signup" />} />
          <Route path="/login" element={<AuthPage mode="login" />} />
          <Route path="/scanner" element={<ScannerPage />} />
          {/* Default to landing for unknown routes */}
          <Route path="*" element={<LandingPage />} />
        </Routes>
      </AnimatePresence>
    </div>
  );
}

export default App;
