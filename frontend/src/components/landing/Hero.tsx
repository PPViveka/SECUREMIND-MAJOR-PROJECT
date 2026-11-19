import { motion } from "motion/react";
import { Shield, ArrowRight, Upload, Code2 } from "lucide-react";
import { Link } from "react-router-dom";

const particles = Array.from({ length: 20 }, (_, index) => ({
  left: (index * 37) % 100,
  top: (index * 53) % 100,
  drift: ((index * 29) % 70) + 10,
  duration: (index % 10) + 10,
}));

export function Hero() {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden bg-[#0A0F1C]">
      {/* Animated Background Grid */}
      <div className="absolute inset-0 opacity-20">
        <div className="absolute inset-0" style={{
          backgroundImage: `linear-gradient(#3B82F6 1px, transparent 1px), linear-gradient(90deg, #3B82F6 1px, transparent 1px)`,
          backgroundSize: '50px 50px',
          animation: 'gridMove 20s linear infinite'
        }} />
      </div>

      {/* Floating Particles */}
      <div className="absolute inset-0 overflow-hidden">
        {particles.map((particle, i) => (
          <motion.div
            key={i}
            className="absolute w-1 h-1 bg-cyan-400 rounded-full"
            style={{ left: `${particle.left}%`, top: `${particle.top}%` }}
            initial={{ opacity: 0 }}
            animate={{
              y: [0, `${particle.drift}vh`],
              opacity: [0, 1, 0]
            }}
            transition={{
              duration: particle.duration,
              repeat: Infinity,
              ease: "linear"
            }}
          />
        ))}
      </div>

      {/* Content */}
      <div className="relative z-10 max-w-7xl mx-auto px-6 text-center pt-20">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="mb-6"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#3B82F6]/10 border border-[#3B82F6]/30 mb-8">
            <Shield className="w-4 h-4 text-[#06B6D4]" />
            <span className="text-[#E5E7EB] text-sm">AI-Powered Security Platform</span>
          </div>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="text-5xl md:text-7xl font-bold text-[#E5E7EB] mb-6 leading-tight" style={{ fontFamily: 'Space Grotesk, sans-serif' }}
        >
          Securing Your Code with{" "}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#3B82F6] via-[#06B6D4] to-[#8B5CF6]">
            AI Intelligence
          </span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="text-xl text-[#9CA3AF] mb-12 max-w-3xl mx-auto"
        >
          Scan code, cloud configs, and IAM policies instantly with SageArmor - your intelligent Digital Security Engineer.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="flex flex-col sm:flex-row gap-4 justify-center items-center"
        >
          <Link to="/scanner">
            <button className="group relative px-8 py-4 bg-gradient-to-r from-[#3B82F6] to-[#06B6D4] rounded-lg text-white flex items-center gap-2 overflow-hidden transition-all duration-300 hover:shadow-[0_0_40px_rgba(59,130,246,0.8)] hover:scale-105 transform hover:-translate-y-1 active:scale-95">
              <span className="relative z-10 flex items-center gap-2">
                <Upload className="w-5 h-5 group-hover:rotate-12 transition-transform duration-300" />
                Launch Scanner
                <ArrowRight className="w-5 h-5 transition-transform group-hover:translate-x-2 duration-300" />
              </span>
              <div className="absolute inset-0 bg-gradient-to-r from-[#06B6D4] to-[#8B5CF6] opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            </button>
          </Link>

          <Link to="/signup">
            <button className="group px-8 py-4 border-2 border-[#3B82F6] rounded-lg text-[#E5E7EB] flex items-center gap-2 hover:bg-[#3B82F6]/20 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1 hover:shadow-[0_0_25px_rgba(59,130,246,0.5)] active:scale-95 relative overflow-hidden">
              <Code2 className="w-5 h-5 group-hover:rotate-12 transition-transform duration-300" />
              Get Started Free
            </button>
          </Link>
        </motion.div>

        {/* Stats */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.8 }}
          className="mt-20 grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto"
        >
          {[
            { value: "96%", label: "Reduction in effort" },
            { value: ">95%", label: "Scan accuracy" },
            { value: "Instant", label: "Real-time results" }
          ].map((stat, index) => (
            <motion.div
              key={index}
              className="group p-6 rounded-lg bg-white/5 backdrop-blur border border-[#3B82F6]/20 hover:border-[#06B6D4]/60 transition-all duration-300 hover:bg-white/10"
            >
              <div className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#3B82F6] to-[#06B6D4] mb-2 group-hover:from-[#06B6D4] group-hover:to-[#8B5CF6] transition-all duration-300">
                {stat.value}
              </div>
              <div className="text-[#9CA3AF] text-sm group-hover:text-[#E5E7EB] transition-colors">{stat.label}</div>
            </motion.div>
          ))}
        </motion.div>
      </div>

      <style>{`
        @keyframes gridMove {
          0% { transform: translateY(0); }
          100% { transform: translateY(50px); }
        }
      `}</style>
    </section>
  );
}
