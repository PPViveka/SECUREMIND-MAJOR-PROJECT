import { Shield, Mail } from "lucide-react";
import { Link } from "react-router-dom";

export function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="py-12 px-6 bg-[#0A0F1C] border-t border-white/10">
      <div className="max-w-7xl mx-auto">
        <div className="grid md:grid-cols-4 gap-12 mb-12">
          {/* Brand */}
          <div className="col-span-1 md:col-span-1">
            <div className="flex items-center gap-3 mb-6">
              <Shield className="w-8 h-8 text-cyan-400" />
              <span className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                 SageArmor
              </span>
            </div>
            <p className="text-[#9CA3AF] text-sm leading-relaxed mb-6">
              Securing the next generation of software with AI-powered security analysis and automated remediation.
            </p>
            <div className="flex gap-4">
              <a href="#" className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-all">
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2A10 10 0 0 0 2 12c0 4.42 2.87 8.17 6.84 9.5.5.08.66-.23.66-.5v-1.69c-2.77.6-3.36-1.34-3.36-1.34-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.89 1.53 2.34 1.09 2.91.83.08-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.92 0-1.11.38-2 1.03-2.71-.1-.25-.45-1.29.1-2.64 0 0 .84-.27 2.75 1.02.79-.22 1.63-.33 2.47-.33.84 0 1.68.11 2.47.33 1.91-1.29 2.75-1.02 2.75-1.02.55 1.35.2 2.39.1 2.64.65.71 1.03 1.6 1.03 2.71 0 3.82-2.34 4.66-4.57 4.91.36.31.69.92.69 1.85V21c0 .27.16.59.67.5C19.14 20.16 22 16.42 22 12A10 10 0 0 0 12 2z"/></svg>
              </a>
              <a href="#" className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-all">
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
              </a>
              <a href="#" className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-all">
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a2.7 2.7 0 0 0-2.7-2.7c-.8 0-1.5.4-2 1v-.8h-3v7.8h3v-4.2c0-.6.5-1.1 1.1-1.1.6 0 1.1.5 1.1 1.1v4.2h3M7 19h3V10H7v9m1.5-10.2c1 0 1.8-.8 1.8-1.8S9.5 5.2 8.5 5.2 6.7 6 6.7 7s.8 1.8 1.8 1.8z"/></svg>
              </a>
            </div>
          </div>

          {/* Product */}
          <div>
            <h4 className="text-white font-semibold mb-6">Product</h4>
            <ul className="space-y-4">
              <li><Link to="/scanner" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Scanner</Link></li>
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Features</a></li>
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Security</a></li>
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Pricing</a></li>
            </ul>
          </div>

          {/* Company */}
          <div>
            <h4 className="text-white font-semibold mb-6">Company</h4>
            <ul className="space-y-4">
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">About Us</a></li>
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Careers</a></li>
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Blog</a></li>
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Contact</a></li>
            </ul>
          </div>

          {/* Support */}
          <div>
            <h4 className="text-white font-semibold mb-6">Support</h4>
            <ul className="space-y-4">
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Documentation</a></li>
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">API Status</a></li>
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Privacy Policy</a></li>
              <li><a href="#" className="text-[#9CA3AF] hover:text-cyan-400 transition-colors text-sm">Terms of Service</a></li>
            </ul>
          </div>
        </div>

        <div className="pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-[#9CA3AF] text-sm">
            © {currentYear} SageArmor AI Security. All rights reserved.
          </p>
          <div className="flex items-center gap-2 text-sm text-[#9CA3AF]">
            <Mail className="w-4 h-4" />
            <span>security@sagearmor.ai</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
