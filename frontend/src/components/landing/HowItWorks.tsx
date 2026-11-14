import { motion } from "motion/react";
import { Upload, Brain, CheckCircle, Wrench } from "lucide-react";

export function HowItWorks() {
  const steps = [
    {
      icon: Upload,
      title: "Input Code",
      description: "Paste a snippet or scan a GitHub repo directly.",
      color: "#3B82F6"
    },
    {
      icon: Brain,
      title: "AI Analysis",
      description: "Deep contextual analysis detects vulnerabilities using AI reasoning.",
      color: "#8B5CF6"
    },
    {
      icon: CheckCircle,
      title: "Validation",
      description: "AI-driven check if vulnerabilities are actually exploitable.",
      color: "#06B6D4"
    },
    {
      icon: Wrench,
      title: "Fix Generation",
      description: "Get instant explainable fix suggestions for every detection.",
      color: "#10B981"
    }
  ];

  return (
    <section className="py-20 px-6 bg-[#0A0F1C] relative overflow-hidden">
      <div className="absolute inset-0 opacity-10">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-[#3B82F6] rounded-full blur-[120px]" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-[#8B5CF6] rounded-full blur-[120px]" />
      </div>

      <div className="max-w-7xl mx-auto relative">
        <motion.div
           initial={{ opacity: 0, y: 20 }}
           whileInView={{ opacity: 1, y: 0 }}
           viewport={{ once: true }}
           className="text-center mb-16"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-[#E5E7EB] mb-4" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            How It <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#3B82F6] to-[#06B6D4]">Works</span>
          </h2>
          <p className="text-[#9CA3AF] text-lg">Secure your application code in four simple steps.</p>
        </motion.div>

        <div className="relative">
          <div className="hidden lg:block absolute top-1/2 left-0 right-0 h-1 bg-gradient-to-r from-[#3B82F6] via-[#8B5CF6] via-[#06B6D4] to-[#10B981] opacity-20 -translate-y-1/2" />

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            {steps.map((step, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.2 }}
                className="relative"
              >
                <div className="bg-white/5 backdrop-blur border border-[#3B82F6]/20 rounded-xl p-6 hover:border-[#06B6D4]/50 transition-all duration-300 hover:transform hover:scale-105 h-full group">
                  <div className="absolute -top-4 -left-4 w-8 h-8 rounded-full bg-gradient-to-br from-[#3B82F6] to-[#06B6D4] flex items-center justify-center text-white text-sm font-bold">
                    {index + 1}
                  </div>

                  <div
                    className="w-16 h-16 rounded-lg flex items-center justify-center mb-4 transition-all"
                    style={{
                      background: `linear-gradient(135deg, ${step.color}20, ${step.color}10)`,
                      border: `1px solid ${step.color}40`
                    }}
                  >
                    <step.icon
                      className="w-8 h-8 transition-transform group-hover:scale-110"
                      style={{ color: step.color }}
                    />
                  </div>

                  <h3 className="text-[#E5E7EB] text-xl font-semibold mb-2">
                    {step.title}
                  </h3>
                  <p className="text-[#9CA3AF] text-sm">
                    {step.description}
                  </p>

                  <div
                    className="absolute inset-0 rounded-xl opacity-0 hover:opacity-100 transition-opacity duration-300 -z-10 blur-xl"
                    style={{ background: `${step.color}20` }}
                  />
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
