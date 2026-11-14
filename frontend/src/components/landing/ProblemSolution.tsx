import { motion } from "motion/react";

export function ProblemSolution() {
  const problems = [
    "Security reviews take hours or days",
    "Misconfigurations go unnoticed",
    "Too many false positives",
    "Lack of security expertise",
    "Manual and error-prone processes"
  ];

  const solutions = [
    "AI scans code in seconds",
    "Real-time detection with validation",
    ">95% accuracy with AI reasoning",
    "AI acts as your security expert",
    "Fully automated with auto-fixes"
  ];

  return (
    <section className="py-20 px-6 bg-gradient-to-b from-[#111827] to-[#0A0F1C]">
      <div className="max-w-7xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-[#E5E7EB] mb-4" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            From <span className="text-[#EF4444]">Problem</span> to{" "}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#3B82F6] to-[#06B6D4]">Solution</span>
          </h2>
          <p className="text-[#9CA3AF] text-lg">Transform your security workflow in minutes, not months.</p>
        </motion.div>

        <div className="grid md:grid-cols-2 gap-8">
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="bg-[#EF4444]/5 backdrop-blur border border-[#EF4444]/20 rounded-2xl p-8"
          >
            <div className="flex items-center gap-3 mb-6">
              <div className="w-12 h-12 rounded-full bg-[#EF4444]/20 flex items-center justify-center">
                <span className="text-[#EF4444] text-xl font-bold">✕</span>
              </div>
              <h3 className="text-2xl font-bold text-[#E5E7EB]">The Problem</h3>
            </div>
            <div className="space-y-4">
              {problems.map((problem, index) => (
                <div key={index} className="flex items-start gap-3 p-4 bg-[#0A0F1C]/50 rounded-lg">
                  <span className="text-[#EF4444] mt-1">✕</span>
                  <p className="text-[#E5E7EB]">{problem}</p>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="bg-gradient-to-br from-[#3B82F6]/10 to-[#06B6D4]/10 backdrop-blur border border-[#3B82F6]/30 rounded-2xl p-8"
          >
            <div className="flex items-center gap-3 mb-6">
              <div className="w-12 h-12 rounded-full bg-gradient-to-br from-[#3B82F6]/30 to-[#06B6D4]/30 flex items-center justify-center">
                <span className="text-[#06B6D4] text-xl font-bold">✓</span>
              </div>
              <h3 className="text-2xl font-bold text-[#E5E7EB]">The Solution</h3>
            </div>
            <div className="space-y-4">
              {solutions.map((solution, index) => (
                <div key={index} className="flex items-start gap-3 p-4 bg-[#0A0F1C]/50 rounded-lg border border-[#3B82F6]/20">
                  <span className="text-[#06B6D4] mt-1">✓</span>
                  <p className="text-[#E5E7EB]">{solution}</p>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
