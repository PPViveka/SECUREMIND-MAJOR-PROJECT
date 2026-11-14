import { motion } from "motion/react";
import { Shield, TrendingUp, AlertTriangle, CheckCircle, Clock, Code } from "lucide-react";

export function DashboardPreview() {
  const recentIssues = [
    { type: "SQL Injection", severity: "High", file: "auth.js", status: "Fixed", time: "2m ago" },
    { type: "XSS Vulnerability", severity: "Medium", file: "profile.tsx", status: "Pending", time: "15m ago" },
    { type: "Weak Crypto", severity: "High", file: "encrypt.py", status: "Fixed", time: "1h ago" },
    { type: "Insecure IAM", severity: "Low", file: "iam.tf", status: "Reviewing", time: "2h ago" }
  ];

  return (
    <section className="py-20 px-6 bg-[#0A0F1C] relative overflow-hidden">
      <div className="absolute inset-0">
        <div className="absolute top-1/4 left-0 w-[500px] h-[500px] bg-[#3B82F6] rounded-full blur-[150px] opacity-10" />
        <div className="absolute bottom-1/4 right-0 w-[500px] h-[500px] bg-[#8B5CF6] rounded-full blur-[150px] opacity-10" />
      </div>

      <div className="max-w-7xl mx-auto relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-[#E5E7EB] mb-4" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            Unified Security <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#3B82F6] to-[#06B6D4]">Dashboard</span>
          </h2>
          <p className="text-[#9CA3AF] text-lg">Monitor, analyze, and protect your entire codebase from one place.</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="bg-white/5 backdrop-blur-xl border border-[#3B82F6]/30 rounded-2xl p-8 shadow-2xl"
        >
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div className="bg-[#0A0F1C] rounded-xl p-4 border border-[#10B981]/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[#9CA3AF] text-sm">Security Score</span>
                <Shield className="w-4 h-4 text-[#10B981]" />
              </div>
              <div className="text-3xl font-bold text-[#10B981]">87/100</div>
              <div className="text-xs text-[#10B981] mt-1">↑ +12 from last week</div>
            </div>

            <div className="bg-[#0A0F1C] rounded-xl p-4 border border-[#EF4444]/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[#9CA3AF] text-sm">Critical Issues</span>
                <AlertTriangle className="w-4 h-4 text-[#EF4444]" />
              </div>
              <div className="text-3xl font-bold text-[#EF4444]">3</div>
              <div className="text-xs text-[#EF4444] mt-1">Needs attention</div>
            </div>

            <div className="bg-[#0A0F1C] rounded-xl p-4 border border-[#06B6D4]/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[#9CA3AF] text-sm">Fixed Today</span>
                <CheckCircle className="w-4 h-4 text-[#06B6D4]" />
              </div>
              <div className="text-3xl font-bold text-[#06B6D4]">24</div>
              <div className="text-xs text-[#06B6D4] mt-1">↑ Great progress!</div>
            </div>

            <div className="bg-[#0A0F1C] rounded-xl p-4 border border-[#8B5CF6]/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[#9CA3AF] text-sm">Avg Fix Time</span>
                <Clock className="w-4 h-4 text-[#8B5CF6]" />
              </div>
              <div className="text-3xl font-bold text-[#8B5CF6]">4m</div>
              <div className="text-xs text-[#8B5CF6] mt-1">↓ 96% faster</div>
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-6 mb-8">
            <div className="bg-[#0A0F1C] rounded-xl p-6 border border-[#3B82F6]/20">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-[#E5E7EB] font-semibold">Vulnerability Trends</h3>
                <TrendingUp className="w-5 h-5 text-[#06B6D4]" />
              </div>
              <div className="flex items-end justify-between h-32 gap-2">
                {[65, 45, 80, 30, 50, 20, 15].map((height, i) => (
                  <div key={i} className="flex-1 flex flex-col items-center">
                    <motion.div
                      initial={{ height: 0 }}
                      whileInView={{ height: `${height}%` }}
                      viewport={{ once: true }}
                      transition={{ delay: i * 0.1, duration: 0.5 }}
                      className="w-full bg-gradient-to-t from-[#3B82F6] to-[#06B6D4] rounded-t"
                    />
                    <span className="text-[#9CA3AF] text-xs mt-2">{['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][i]}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-[#0A0F1C] rounded-xl p-6 border border-[#3B82F6]/20">
              <h3 className="text-[#E5E7EB] font-semibold mb-4">Severity Distribution</h3>
              <div className="space-y-3">
                {[
                  { label: "Critical", value: 3, color: "#EF4444", percent: 15 },
                  { label: "High", value: 8, color: "#F59E0B", percent: 40 },
                  { label: "Medium", value: 12, color: "#3B82F6", percent: 60 },
                  { label: "Low", value: 5, color: "#10B981", percent: 25 }
                ].map((item, i) => (
                  <div key={i}>
                    <div className="flex items-center justify-between text-sm mb-1">
                      <span className="text-[#9CA3AF]">{item.label}</span>
                      <span className="text-[#E5E7EB]">{item.value}</span>
                    </div>
                    <div className="h-2 bg-[#1F2937] rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        whileInView={{ width: `${item.percent}%` }}
                        viewport={{ once: true }}
                        transition={{ delay: i * 0.1, duration: 0.8 }}
                        className="h-full rounded-full"
                        style={{ backgroundColor: item.color }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="bg-[#0A0F1C] rounded-xl p-6 border border-[#3B82F6]/20">
            <h3 className="text-[#E5E7EB] font-semibold mb-4">Recent Detections</h3>
            <div className="space-y-3">
              {recentIssues.map((issue, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: index * 0.1 }}
                  className="flex items-center justify-between p-3 bg-white/5 rounded-lg hover:bg-white/10 transition-all cursor-pointer"
                >
                  <div className="flex items-center gap-3 flex-1">
                    <div className={`w-2 h-2 rounded-full ${
                      issue.severity === "High" ? "bg-[#EF4444]" :
                      issue.severity === "Medium" ? "bg-[#F59E0B]" : "bg-[#10B981]"
                    }`} />
                    <Code className="w-4 h-4 text-[#9CA3AF]" />
                    <div className="flex-1">
                      <div className="text-[#E5E7EB] text-sm font-medium">{issue.type}</div>
                      <div className="text-[#9CA3AF] text-xs">{issue.file}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className={`text-xs px-2 py-1 rounded ${
                      issue.status === "Fixed" ? "bg-[#10B981]/20 text-[#10B981]" :
                      issue.status === "Pending" ? "bg-[#F59E0B]/20 text-[#F59E0B]" :
                      "bg-[#3B82F6]/20 text-[#3B82F6]"
                    }`}>{issue.status}</span>
                    <span className="text-[#9CA3AF] text-xs">{issue.time}</span>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
