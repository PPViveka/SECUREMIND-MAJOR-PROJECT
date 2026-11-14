import { Hero } from '../components/landing/Hero';
import { HowItWorks } from '../components/landing/HowItWorks';
import { Features } from '../components/landing/Features';
import { DashboardPreview } from '../components/landing/DashboardPreview';
import { ProblemSolution } from '../components/landing/ProblemSolution';
import { ImpactStats } from '../components/landing/ImpactStats';
import { FinalCTA } from '../components/landing/FinalCTA';
import { Footer } from '../components/landing/Footer';
import { ScrollReveal } from '../components/shared/ScrollReveal';
import { PageTransition } from '../components/shared/PageTransition';

export default function LandingPage() {
  return (
    <PageTransition>
      <div className="bg-[#0A0F1C]">
        <Hero />
        <ScrollReveal direction="up">
          <HowItWorks />
        </ScrollReveal>
        <ScrollReveal direction="up" delay={100}>
          <Features />
        </ScrollReveal>
        <ScrollReveal direction="scale" delay={150}>
          <DashboardPreview />
        </ScrollReveal>
        <ScrollReveal direction="left">
          <ProblemSolution />
        </ScrollReveal>
        <ScrollReveal direction="up" delay={200}>
          <ImpactStats />
        </ScrollReveal>
        <ScrollReveal direction="scale">
          <FinalCTA />
        </ScrollReveal>
        <Footer />
      </div>
    </PageTransition>
  );
}
