import { motion } from "motion/react";
import { ArrowRight, Sparkles, Shield, Rocket } from "lucide-react";
import { Link } from "react-router-dom";

export function FinalCTA() {
  return (
    <section className="py-20 px-6 bg-gradient-to-b from-[#111827] to-[#0A0F1C] relative overflow-hidden">
      <div className="absolute inset-0">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-[#3B82F6] rounded-full blur-[150px] opacity-20 animate-pulse" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-[#8B5CF6] rounded-full blur-[150px] opacity-20 animate-pulse" style={{ animationDelay: '1s' }} />
      </div>

      <div className="max-w-4xl mx-auto relative">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-xl border border-[#3B82F6]/30 rounded-3xl p-12 text-center relative overflow-hidden"
        >
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-[#3B82F6] via-[#8B5CF6] via-[#06B6D4] to-[#10B981]" />

          <motion.div animate={{ y: [0, -10, 0] }} transition={{ duration: 3, repeat: Infinity }} className="absolute top-8 left-8 w-12 h-12 rounded-full bg-[#3B82F6]/20 flex items-center justify-center">
            <Shield className="w-6 h-6 text-[#3B82F6]" />
          </motion.div>

          <motion.div animate={{ y: [0, 10, 0] }} transition={{ duration: 3, repeat: Infinity, delay: 0.5 }} className="absolute top-8 right-8 w-12 h-12 rounded-full bg-[#8B5CF6]/20 flex items-center justify-center">
            <Sparkles className="w-6 h-6 text-[#8B5CF6]" />
          </motion.div>

          <motion.div animate={{ y: [0, -10, 0] }} transition={{ duration: 3, repeat: Infinity, delay: 1 }} className="absolute bottom-8 left-1/2 -translate-x-1/2 w-12 h-12 rounded-full bg-[#06B6D4]/20 flex items-center justify-center">
            <Rocket className="w-6 h-6 text-[#06B6D4]" />
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: 0.2 }}>
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#3B82F6]/10 border border-[#3B82F6]/30 mb-6">
              <Sparkles className="w-4 h-4 text-[#06B6D4]" />
              <span className="text-[#E5E7EB] text-sm">Start Free • No Credit Card Required</span>
            </div>

            <h2 className="text-4xl md:text-6xl font-bold text-[#E5E7EB] mb-6 leading-tight" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
              Start Securing Your{" "}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#3B82F6] via-[#06B6D4] to-[#8B5CF6]">
                Code Now
              </span>
            </h2>

            <p className="text-xl text-[#9CA3AF] mb-8 max-w-2xl mx-auto">
              Join developers who have transformed their security workflow with SageArmor AI automation.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-8">
              <Link to="/signup">
                <button className="group relative px-8 py-4 bg-gradient-to-r from-[#3B82F6] to-[#06B6D4] rounded-lg text-white text-lg font-semibold flex items-center gap-2 overflow-hidden transition-all duration-300 hover:shadow-[0_0_40px_rgba(59,130,246,0.6)] hover:scale-105">
                  <span className="relative z-10 flex items-center gap-2">
                    Get Started Free
                    <ArrowRight className="w-5 h-5 transition-transform group-hover:translate-x-2" />
                  </span>
                </button>
              </Link>

              <Link to="/scanner">
                <button className="px-8 py-4 border-2 border-[#3B82F6] rounded-lg text-[#E5E7EB] text-lg font-semibold hover:bg-[#3B82F6]/10 transition-all duration-300">
                  Try Live Demo
                </button>
              </Link>
            </div>
          </motion.div>
        </motion.div>

        <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6 text-center">
            <div className="p-6 bg-white/5 backdrop-blur rounded-xl border border-[#3B82F6]/20">
              <div className="text-3xl font-bold text-[#06B6D4] mb-2">50K+</div>
              <p className="text-[#9CA3AF]">Vulnerabilities Found</p>
            </div>
            <div className="p-6 bg-white/5 backdrop-blur rounded-xl border border-[#3B82F6]/20">
              <div className="text-3xl font-bold text-[#8B5CF6] mb-2">1000+</div>
              <p className="text-[#9CA3AF]">Developers Protected</p>
            </div>
            <div className="p-6 bg-white/5 backdrop-blur rounded-xl border border-[#3B82F6]/20">
              <div className="text-3xl font-bold text-[#10B981] mb-2">99.9%</div>
              <p className="text-[#9CA3AF]">Uptime Reliability</p>
            </div>
        </div>
      </div>
    </section>
  );
}
