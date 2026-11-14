import { motion } from "motion/react";
import { Zap, Brain, Search, Wrench, GitBranch, BarChart3, Target, MessageSquare } from "lucide-react";

export function Features() {
  const features = [
    {
      icon: Zap,
      title: "Real-time Scanning",
      description: "Instant vulnerability detection as you code, with AI-driven context.",
      gradient: "from-[#3B82F6] to-[#06B6D4]"
    },
    {
      icon: Brain,
      title: "AI Reasoning",
      description: "Context-aware analysis that understands why vulnerabilities matter.",
      gradient: "from-[#8B5CF6] to-[#3B82F6]"
    },
    {
      icon: Search,
      title: "Exploit Validation",
      description: "Filters out false positives by testing actual exploitability.",
      gradient: "from-[#06B6D4] to-[#10B981]"
    },
    {
      icon: Wrench,
      title: "Auto-Fix",
      description: "Get ready-to-use code fixes with detailed explanations.",
      gradient: "from-[#10B981] to-[#06B6D4]"
    },
    {
      icon: GitBranch,
      title: "Git Integration",
      description: "Seamlessly integrate with your existing GitHub/GitLab workflow.",
      gradient: "from-[#3B82F6] to-[#8B5CF6]"
    },
    {
      icon: BarChart3,
      title: "Risk Dashboard",
      description: "Track security metrics and trends across all your projects.",
      gradient: "from-[#8B5CF6] to-[#06B6D4]"
    },
    {
      icon: Target,
      title: "High Accuracy",
      description: "95% accuracy means you focus only on real threats.",
      gradient: "from-[#06B6D4] to-[#3B82F6]"
    },
    {
      icon: MessageSquare,
      title: "Security Copilot",
      description: "Chat with our AI to understand and fix any vulnerability.",
      gradient: "from-[#10B981] to-[#3B82F6]"
    }
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
            Powerful <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#3B82F6] to-[#06B6D4]">Features</span>
          </h2>
          <p className="text-[#9CA3AF] text-lg max-w-2xl mx-auto">
            Everything you need to transform your security workflow from manual to automated.
          </p>
        </motion.div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((feature, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ scale: 1.05, y: -10 }}
              className="group relative bg-white/5 backdrop-blur rounded-xl p-6 border border-[#3B82F6]/20 hover:border-[#06B6D4]/60 transition-all duration-300 cursor-pointer overflow-hidden"
            >
              <div className="absolute inset-0 bg-gradient-to-br from-[#3B82F6]/0 via-[#06B6D4]/0 to-[#8B5CF6]/0 group-hover:from-[#3B82F6]/10 group-hover:via-[#06B6D4]/5 group-hover:to-[#8B5CF6]/10 transition-all duration-500 -z-10" />
              
              <motion.div className="relative mb-4" whileHover={{ rotate: 360 }} transition={{ duration: 0.6 }}>
                <div className={`w-12 h-12 rounded-lg bg-gradient-to-br ${feature.gradient} opacity-20 absolute blur-sm group-hover:opacity-40 transition-all`} />
                <div className={`w-12 h-12 rounded-lg flex items-center justify-center relative bg-gradient-to-br ${feature.gradient} bg-opacity-10`}>
                  <feature.icon className="w-6 h-6 text-[#06B6D4] group-hover:text-white transition-all scale-100 group-hover:scale-125" />
                </div>
              </motion.div>

              <h3 className="text-[#E5E7EB] font-semibold mb-2 group-hover:text-transparent group-hover:bg-clip-text group-hover:bg-gradient-to-r group-hover:from-[#3B82F6] group-hover:to-[#06B6D4] transition-all">
                {feature.title}
              </h3>
              <p className="text-[#9CA3AF] text-sm group-hover:text-[#E5E7EB] transition-colors">
                {feature.description}
              </p>
              
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-[#3B82F6] via-[#06B6D4] to-[#8B5CF6] transform scale-x-0 group-hover:scale-x-100 transition-transform duration-500 origin-left" />
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
