import { motion, useInView } from "motion/react";
import { useRef, useState, useEffect } from "react";

function AnimatedNumber({ target, suffix = "", prefix = "" }: { target: number; suffix?: string; prefix?: string }) {
  const [count, setCount] = useState(0);
  const ref = useRef(null);
  const isInView = useInView(ref, { once: true });

  useEffect(() => {
    if (isInView) {
      let start = 0;
      const duration = 2000;
      const increment = target / (duration / 16);

      const timer = setInterval(() => {
        start += increment;
        if (start >= target) {
          setCount(target);
          clearInterval(timer);
        } else {
          setCount(Math.floor(start));
        }
      }, 16);

      return () => clearInterval(timer);
    }
  }, [isInView, target]);

  return (
    <span ref={ref}>
      {prefix}{count}{suffix}
    </span>
  );
}

export function ImpactStats() {
  const stats = [
    {
      value: 96,
      suffix: "%",
      label: "Reduction in Manual Effort",
      description: "Automate security reviews and free up your team.",
      color: "from-[#3B82F6] to-[#06B6D4]"
    },
    {
      value: 95,
      suffix: "%+",
      prefix: ">",
      label: "Accuracy in Detections",
      description: "AI validation ensures only real threats are flagged.",
      color: "from-[#8B5CF6] to-[#3B82F6]"
    },
    {
      value: 4,
      label: "Seconds Average Fix Time",
      description: "Days to seconds - transform your security MTTR.",
      color: "from-[#06B6D4] to-[#10B981]"
    },
    {
      value: 10,
      suffix: "x",
      label: "Faster Code Shipping",
      description: "Security that moves at the speed of your product releases.",
      color: "from-[#10B981] to-[#06B6D4]"
    }
  ];

  return (
    <section className="py-20 px-6 bg-[#0A0F1C] relative overflow-hidden">
      <div className="absolute inset-0">
        {[...Array(3)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute h-px bg-gradient-to-r from-transparent via-[#3B82F6]/30 to-transparent"
            style={{ top: `${25 + i * 25}%`, left: 0, right: 0 }}
            animate={{ x: ['-100%', '100%'] }}
            transition={{ duration: 10 + i * 2, repeat: Infinity, ease: "linear", delay: i * 2 }}
          />
        ))}
      </div>

      <div className="max-w-7xl mx-auto relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-[#E5E7EB] mb-4" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            Measurable <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#3B82F6] to-[#06B6D4]">Impact</span>
          </h2>
          <p className="text-[#9CA3AF] text-lg">Real results that transform your security posture.</p>
        </motion.div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {stats.map((stat, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1 }}
              className="relative group"
            >
              <div className="bg-white/5 backdrop-blur border border-[#3B82F6]/20 rounded-xl p-6 h-full hover:border-[#06B6D4]/50 transition-all duration-300">
                <div className={`absolute inset-0 rounded-xl bg-gradient-to-r ${stat.color} opacity-0 group-hover:opacity-20 blur-xl transition-opacity duration-300 -z-10`} />
                
                <div className={`text-5xl font-bold mb-3 text-transparent bg-clip-text bg-gradient-to-r ${stat.color}`} style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                  <AnimatedNumber target={stat.value} suffix={stat.suffix} prefix={stat.prefix} />
                </div>

                <h3 className="text-[#E5E7EB] font-semibold mb-2">{stat.label}</h3>
                <p className="text-[#9CA3AF] text-sm">{stat.description}</p>

                <motion.div
                  initial={{ width: 0 }}
                  whileInView={{ width: "100%" }}
                  viewport={{ once: true }}
                  transition={{ delay: index * 0.1 + 0.5, duration: 0.8 }}
                  className={`h-1 rounded-full bg-gradient-to-r ${stat.color} mt-4`}
                />
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
