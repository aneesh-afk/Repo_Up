import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Code2, Network, AlertTriangle, Clock,
  Download, Lock, ChevronRight, File, ShieldAlert,
  Activity, CheckCircle2, ShieldCheck, Database, LayoutDashboard, Zap, Flame, XCircle, AlertCircle
} from 'lucide-react';
import { GraphView } from './GraphView';
import { DependencyGraphBackground } from './DependencyGraphBackground';
import { CodeViewer } from './CodeViewer';
import { API_BASE } from '../App';
interface Finding {
  category: string;
  title: string;
  description: string;
  severity: 'High' | 'Medium' | 'Low';
  file?: string;
  line?: number;
  rule_id?: string;
  language?: string;
  autofix_available?: boolean;
  resolution?: string;
  cwe?: string;
  source?: string;
}

interface PatchData {
  rule_id: string;
  language: string;
  file: string;
  start_line: number;
  old_text: string;
  new_text: string;
  diff: string;
  verification_status: string;
}

interface Rubric {
  final_score: number;
  structural_score: number;
  metrics_score: number;
  security_score: number;
  category_breakdown: {
    modularity: number;
    analysability: number;
    modifiability: number;
    testability: number;
  };
  metric_ratings: {
    cof: 'good' | 'regular' | 'bad';
    afferent_couplings: 'good' | 'regular' | 'bad';
    public_fields: 'good' | 'regular' | 'bad';
    public_methods: 'good' | 'regular' | 'bad';
    dit: 'good' | 'regular' | 'bad';
    lcom: 'good' | 'regular' | 'bad';
  };
}

interface AnalysisResult {
  language?: string | string[];
  framework?: string | string[];
  files?: number;
  score?: number;
  issues?: Finding[];
  tree?: string[];
  rubric?: Rubric;
  graph?: { nodes: { id: string; label: string }[]; edges: { source: string; target: string }[] };
  session_id?: string;
}

interface ResultsProps {
  data: AnalysisResult | null;
  onReset: () => void;
  onApplyAll: (findings: Finding[]) => void;
}

export const Results: React.FC<ResultsProps> = ({ data, onReset, onApplyAll }) => {
  const [showGraph, setShowGraph] = useState(false);
  const [filterCategory, setFilterCategory] = useState<string>('All');
  const [viewingFinding, setViewingFinding] = useState<Finding | null>(null);
  const [fixFinding, setFixFinding] = useState<Finding | null>(null);
  const [patchData, setPatchData] = useState<PatchData | null>(null);
  const [patchExplanation, setPatchExplanation] = useState<string | null>(null);
  const [patchLoading, setPatchLoading] = useState(false);
  const [patchError, setPatchError] = useState<string | null>(null);

  const d = data ?? {};
  const rubric: Rubric | undefined = d.rubric;

  const score = rubric?.final_score ?? (d.score ?? 0);
  const structuralScore = rubric?.structural_score ?? 0;
  const metricsScore = rubric?.metrics_score ?? 0;
  const securityScore = rubric?.security_score ?? 100;

  const language = d.language ?? 'Unknown';
  const framework = d.framework ?? 'Unknown';
  const filesCount = d.files ?? 0;
  const issues: Finding[] = d.issues ?? [];
  const tree: string[] = d.tree ?? [];
  const sessionId: string = (d as any).session_id ?? '';

  const handleDownloadReport = () => {
    const report = {
      time: new Date().toISOString().split('T')[0],
      language,
      framework,
      score,
      issues,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'repo-up-report.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const scrollToSection = (e: React.MouseEvent, id: string) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  };

  const getScoreColor = (val: number): string => {
    if (val >= 80) return 'text-[#10B981]';
    if (val >= 50) return 'text-[#F59E0B]';
    return 'text-[#EF4444]';
  };

  const getSeverityStyle = (sev: string): string => {
    switch (sev?.toLowerCase()) {
      case 'high': return 'bg-[#EF4444]/20 text-[#EF4444] border-[#EF4444]/30';
      case 'medium': return 'bg-[#F59E0B]/20 text-[#F59E0B] border-[#F59E0B]/30';
      default: return 'bg-[#3B82F6]/20 text-[#3B82F6] border-[#3B82F6]/30';
    }
  };

  const getRatingStyle = (rating: string): string => {
    switch (rating) {
      case 'good': return 'bg-[#059669]/20 text-[#34D399] border-[#34D399]/30';
      case 'regular': return 'bg-[#D97706]/20 text-[#FBBF24] border-[#FBBF24]/30';
      case 'bad': return 'bg-[#991B1B]/20 text-[#F87171] border-[#F87171]/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getCategoryIcon = (cat: string) => {
    switch (cat) {
      case 'Structural': return <Network size={16} className="text-[#6D5EF0]" />;
      case 'Metrics': return <Activity size={16} className="text-[#6D5EF0]" />;
      case 'Security': return <ShieldAlert size={16} className="text-[#EF4444]" />;
      case 'Code Smell': return <Flame size={16} className="text-[#F59E0B]" />;
      default: return <AlertTriangle size={16} className="text-[#F59E0B]" />;
    }
  };

  const filteredIssues = issues
    .filter(i => filterCategory === 'All' || i.category === filterCategory)
    .sort((a, b) => {
      const rank: Record<string, number> = { High: 3, Medium: 2, Low: 1 };
      return (rank[b.severity] || 0) - (rank[a.severity] || 0);
    });

  const maskSecret = (desc: string): string =>
    desc.replace(/([A-Za-z0-9_]{4})[A-Za-z0-9_]{8,}([A-Za-z0-9_]{4})/g, '$1••••••••$2');

  const displayScore = Math.round(score);

  /** Issues for the currently-viewed file (for CodeViewer markers). */
  const viewingFileIssues: Finding[] = viewingFinding?.file
    ? issues.filter(i => i.file && i.file.replace(/\\/g, '/') === viewingFinding.file!.replace(/\\/g, '/'))
    : [];

  /** Score label — calm, non-judgmental per Design.md. */
  const scoreLabel =
    score >= 85 ? 'Production Ready'
    : score >= 60 ? 'Needs Some Attention'
    : 'Review Recommended';

  return (
    <div className="flex h-full w-full bg-[#05050A] text-white overflow-hidden font-sans relative">
      {/* Background Texture */}
      <div className="absolute inset-0 z-0 pointer-events-none opacity-[0.08]" style={{ maskImage: 'radial-gradient(ellipse at center, black, transparent 80%)', WebkitMaskImage: 'radial-gradient(ellipse at center, black, transparent 80%)' }}>
        <DependencyGraphBackground />
      </div>

      {/* SIDEBAR */}
      <div className="w-64 border-r border-white/5 bg-[#05050A]/80 backdrop-blur-xl p-4 flex flex-col shrink-0 relative z-20 overflow-y-auto overflow-x-hidden">
        <div className="flex items-center gap-2 mb-8 px-2 cursor-pointer group" onClick={onReset}>
          <div className="text-transparent bg-clip-text bg-gradient-to-r from-[#6D5EF0] to-[#3B82F6]">
            <Code2 size={24} className="text-[#6D5EF0]" />
          </div>
          <span className="font-bold text-xl tracking-tight text-white group-hover:text-transparent group-hover:bg-clip-text group-hover:bg-gradient-to-r from-[#6D5EF0] to-[#3B82F6] transition-all">
            Repo-Up
          </span>
        </div>

        <nav className="space-y-1 mb-8">
          <a href="#overview" onClick={(e) => scrollToSection(e, 'overview')} className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-colors focus:bg-[#6D5EF0]/10 focus:text-[#6D5EF0]">
            <LayoutDashboard size={18} /> Dashboard
          </a>
          <a href="#iso" onClick={(e) => scrollToSection(e, 'iso')} className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-colors focus:bg-[#6D5EF0]/10 focus:text-[#6D5EF0]">
            <Activity size={18} /> ISO 25010
          </a>
          <a href="#findings" onClick={(e) => scrollToSection(e, 'findings')} className="flex items-center justify-between px-3 py-2.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-colors focus:bg-[#6D5EF0]/10 focus:text-[#6D5EF0]">
            <div className="flex items-center gap-3"><ShieldAlert size={18} /> Findings</div>
            <span className="bg-[#EF4444]/20 text-[#EF4444] text-xs px-2 py-0.5 rounded-full font-bold">{issues.length}</span>
          </a>
          <a href="#architecture" onClick={(e) => scrollToSection(e, 'architecture')} className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-colors focus:bg-[#6D5EF0]/10 focus:text-[#6D5EF0]">
            <Network size={18} /> Architecture
          </a>
        </nav>

        <div className="mt-4 px-3 mb-auto">
          <div className="text-[10px] font-bold text-gray-500 tracking-wider mb-3 uppercase">Session Details</div>
          <div className="flex items-center gap-2 mb-3">
            <span className="font-medium text-sm text-gray-300">Target</span>
            <span className="bg-[#6D5EF0]/20 border border-[#6D5EF0]/30 text-[#8B5CF6] text-[10px] px-1.5 py-0.5 rounded">
              {Array.isArray(language) ? language.join(', ') : language}
            </span>
          </div>
          <div className="space-y-2 text-xs text-gray-400">
            <div className="flex items-center gap-2"><File size={12} /> {filesCount} Files Parsed</div>
            <div className="flex items-center gap-2"><Clock size={12} /> Live Telemetry</div>
          </div>
        </div>

        {/* CTA Phase 4 */}
        <div className="mt-8 bg-gradient-to-b from-white/5 to-transparent border border-white/10 rounded-xl p-4 text-center relative overflow-hidden group">
          <div className="absolute inset-0 bg-[#6D5EF0]/5 group-hover:bg-[#6D5EF0]/10 transition-colors" />
          <h4 className="font-bold text-sm mb-2 text-white relative z-10 flex items-center justify-center gap-2"><Zap size={14} className="text-[#F59E0B]" /> Auto-Fix</h4>
          <p className="text-xs text-gray-400 mb-4 relative z-10">Deploy fixes to secure sandbox</p>
          <button onClick={() => onApplyAll(issues)} className="w-full py-2 bg-gradient-to-r from-[#6D5EF0] to-[#3B82F6] hover:shadow-[0_0_15px_rgba(109,94,240,0.5)] border border-transparent rounded-lg text-xs font-bold text-white flex items-center justify-center gap-2 relative z-10 transition-all cursor-pointer">
            <Zap size={12} /> Apply All Changes
          </button>
        </div>
      </div>

      {/* MAIN CONTENT */}
      <div className="flex-1 flex flex-col min-w-0 relative z-10 h-full">

        {/* Header */}
        <header className="h-16 border-b border-white/5 bg-[#05050A]/70 backdrop-blur-md flex items-center justify-between px-8 shrink-0">
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <span>Repo-Up</span> <ChevronRight size={14} /> <span className="text-white font-medium">Dashboard</span>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setShowGraph(!showGraph)}
              className="flex items-center gap-2 text-xs font-medium transition-all px-4 py-2 border rounded-lg bg-gradient-to-r from-[#6D5EF0] to-[#3B82F6] text-white border-transparent hover:shadow-[0_0_15px_rgba(109,94,240,0.4)]"
            >
              <Network size={14} /> Full Graph Explorer
            </button>
            <button
              onClick={handleDownloadReport}
              className="flex items-center gap-2 text-xs font-medium text-gray-300 hover:text-white transition-colors px-3 py-2 border border-white/10 rounded-lg hover:border-white/30 bg-white/5"
            >
              <Download size={14} /> Export Report
            </button>
            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-[#6D5EF0] to-[#3B82F6] text-white flex items-center justify-center text-xs font-bold shadow-lg ml-2">
              US
            </div>
          </div>
        </header>

        {/* Scrollable Dashboard */}
        <div className="flex-1 overflow-y-auto p-6 md:p-8 space-y-8 scroll-smooth relative">

          <AnimatePresence>
            {showGraph && d.graph && (
              <GraphView
                nodes={d.graph.nodes}
                edges={d.graph.edges}
                issues={issues}
                sessionId={sessionId}
                onClose={() => setShowGraph(false)}
              />
            )}
          </AnimatePresence>

          {/* CodeViewer overlay */}
          <AnimatePresence>
            {viewingFinding && viewingFinding.file && sessionId && (
              <CodeViewer
                sessionId={sessionId}
                filePath={viewingFinding.file}
                line={viewingFinding.line ?? 1}
                fileIssues={viewingFileIssues}
                onClose={() => setViewingFinding(null)}
              />
            )}
          </AnimatePresence>

          {/* TOP SUMMARY BAR */}
          <motion.div
            id="overview"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="grid grid-cols-1 md:grid-cols-3 gap-6"
          >
            {/* BIG SCORE CARD */}
            <div className="col-span-1 md:col-span-2 bg-[#0B0C10]/60 backdrop-blur-xl border border-white/10 rounded-2xl p-8 relative flex items-center gap-8 shadow-2xl">
              {/* Circular Progress */}
              <div className="relative w-40 h-40 shrink-0">
                <svg className="w-full h-full transform -rotate-90 overflow-visible" viewBox="0 0 100 100">
                  <defs>
                    <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#6D5EF0" />
                      <stop offset="100%" stopColor="#3B82F6" />
                    </linearGradient>
                  </defs>
                  <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
                  <circle cx="50" cy="50" r="45" fill="none" stroke="url(#scoreGrad)" strokeWidth="8" strokeDasharray="282.7" strokeDashoffset={282.7 - (282.7 * Math.min(score, 100)) / 100} className="drop-shadow-[0_0_10px_rgba(109,94,240,0.6)] transition-all duration-1000" />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white to-gray-400">{displayScore}</span>
                </div>
              </div>

              {/* Info */}
              <div className="flex-1">
                <div className="text-[10px] font-bold text-[#6D5EF0] tracking-wider mb-2 uppercase flex items-center gap-2"><Activity size={12} /> Overall Readiness</div>
                <h2 className="text-3xl font-bold mb-2 text-white">{scoreLabel}</h2>
                <p className="text-sm text-gray-400 mb-6 max-w-md leading-relaxed">
                  Your codebase structure and metrics have been analysed. Review the findings below to address architectural debt and security concerns.
                </p>

                {/* Sub-scores */}
                {rubric && (
                  <div className="flex gap-4">
                    <div className="bg-white/5 border border-white/10 px-4 py-2 rounded-lg flex flex-col min-w-[100px]">
                      <span className="text-[10px] text-gray-400 uppercase tracking-wider font-semibold">Structure</span>
                      <span className={`text-xl font-bold ${getScoreColor(structuralScore)}`}>{structuralScore}</span>
                    </div>
                    <div className="bg-white/5 border border-white/10 px-4 py-2 rounded-lg flex flex-col min-w-[100px]">
                      <span className="text-[10px] text-gray-400 uppercase tracking-wider font-semibold">Metrics</span>
                      <span className={`text-xl font-bold ${getScoreColor(metricsScore)}`}>{metricsScore}</span>
                    </div>
                    <div className="bg-white/5 border border-white/10 px-4 py-2 rounded-lg flex flex-col min-w-[100px]">
                      <span className="text-[10px] text-gray-400 uppercase tracking-wider font-semibold">Security</span>
                      <span className={`text-xl font-bold ${getScoreColor(securityScore)}`}>{securityScore}</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* TIMELINE */}
            <div className="col-span-1 bg-[#0B0C10]/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6 shadow-xl flex flex-col">
              <div className="flex items-center gap-2 mb-6">
                <Clock size={16} className="text-[#3B82F6]" />
                <h3 className="font-bold text-sm text-white">Analysis Pipeline</h3>
              </div>
              <div className="flex-1 flex flex-col justify-center space-y-4 relative">
                <div className="absolute left-2.5 top-2 bottom-2 w-[1px] bg-white/10 -z-10" />
                {[
                  'Parse AST',
                  'Extract Entities',
                  'Build Dependency Graph',
                  'Run Security Rules',
                  'Compute ISO Metrics',
                  'External Security Assessment',
                ].map((label, i) => (
                  <div key={i} className="flex items-center gap-4">
                    <div className="w-5 h-5 rounded-full bg-gradient-to-r from-[#6D5EF0] to-[#3B82F6] flex items-center justify-center shrink-0">
                      <CheckCircle2 size={12} className="text-white" />
                    </div>
                    <span className="text-sm text-gray-300 font-medium">{label}</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>

          {/* ISO 25010 BREAKDOWN */}
          {rubric && (
            <motion.div
              id="iso"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Database size={18} className="text-[#6D5EF0]" /> ISO/IEC 25010 Code Quality</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {(['Modularity', 'Analysability', 'Modifiability', 'Testability'] as const).map((cat, idx) => {
                  const val = rubric.category_breakdown[cat.toLowerCase() as keyof typeof rubric.category_breakdown];
                  return (
                    <div key={idx} className="bg-[#0B0C10]/60 backdrop-blur-xl border border-white/10 rounded-xl p-5 relative overflow-hidden group hover:border-[#6D5EF0]/40 transition-colors">
                      <div className="flex items-center justify-between mb-4">
                        <span className="font-semibold text-sm text-gray-200">{cat}</span>
                        <Activity size={14} className="text-gray-500 group-hover:text-[#6D5EF0] transition-colors" />
                      </div>
                      <div className="text-3xl font-black text-white flex items-baseline gap-1 mb-3">
                        {val} <span className="text-xs font-medium text-gray-500">/100</span>
                      </div>
                      <div className="h-1.5 w-full bg-black/50 rounded-full overflow-hidden">
                        <div className="h-full bg-gradient-to-r from-[#6D5EF0] to-[#3B82F6] rounded-full" style={{ width: `${val}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </motion.div>
          )}

          {/* METRIC RATINGS */}
          {rubric && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.15 }}
              className="bg-[#0B0C10]/60 backdrop-blur-xl border border-white/10 rounded-2xl flex flex-col shadow-xl overflow-hidden"
            >
              <div className="p-5 border-b border-white/10 flex items-center justify-between bg-black/20">
                <h3 className="font-bold flex items-center gap-2 text-white">
                  <Activity size={16} className="text-[#3B82F6]" />
                  Codebase Metrics
                </h3>
              </div>
              <div className="p-5 overflow-x-auto">
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  {[
                    { key: 'cof', label: 'Coupling Factor (COF)', tip: 'System-level connectivity ratio' },
                    { key: 'afferent_couplings', label: 'Afferent Couplings (avg)', tip: 'Average in-degree per file' },
                    { key: 'public_fields', label: 'Public Fields (avg)', tip: 'Average public fields per class' },
                    { key: 'public_methods', label: 'Public Methods / WMC proxy (avg)', tip: 'Average public method count per class' },
                    { key: 'dit', label: 'Inheritance Depth / DIT (avg)', tip: 'Average depth of inheritance tree' },
                    { key: 'lcom', label: 'Cohesion / LCOM proxy (avg)', tip: 'Average LCOM proxy per class' },
                  ].map((m) => {
                    const rating = rubric.metric_ratings[m.key as keyof typeof rubric.metric_ratings] ?? 'good';
                    return (
                      <div key={m.key} title={m.tip} className="bg-black/30 border border-white/5 p-4 rounded-xl flex items-center justify-between hover:bg-white/5 transition-colors">
                        <span className="text-sm font-semibold text-gray-300">{m.label}</span>
                        <span className={`text-[10px] uppercase tracking-wider font-bold px-2.5 py-1 rounded-full border ${getRatingStyle(rating)}`}>
                          {rating}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </motion.div>
          )}

          {/* FINDINGS LIST */}
          <motion.div
            id="findings"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="flex flex-col xl:flex-row gap-6"
          >
            {/* Findings Section */}
            <div className="flex-1 bg-[#0B0C10]/60 backdrop-blur-xl border border-white/10 rounded-2xl flex flex-col shadow-xl overflow-hidden min-h-[500px]">
              <div className="p-5 border-b border-white/10 flex items-center justify-between bg-black/20">
                <h3 className="font-bold flex items-center gap-2 text-white">
                  <ShieldAlert size={16} className="text-[#F59E0B]" />
                  Analysis Findings
                </h3>

                {/* Filters */}
                <div className="flex gap-2">
                  {['All', 'Structural', 'Metrics', 'Security', 'Code Smell'].map(cat => (
                    <button
                      key={cat}
                      onClick={() => setFilterCategory(cat)}
                      className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all ${filterCategory === cat ? 'bg-gradient-to-r from-[#6D5EF0] to-[#3B82F6] text-white shadow-md border border-transparent' : 'bg-white/5 border border-white/10 text-gray-400 hover:text-white hover:bg-white/10'}`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>

              <div className="p-5 flex-1 overflow-y-auto">
                <ul className="space-y-4">
                  {filteredIssues.length === 0 && (
                    <div className="text-center text-gray-500 py-20 text-sm flex flex-col items-center">
                      <ShieldCheck size={48} className="text-[#10B981] mb-4 opacity-50" />
                      No findings in this category.
                    </div>
                  )}
                  {filteredIssues.map((issue, i) => {
                    const isClickable = Boolean(issue.file);
                    return (
                      <li
                        key={i}
                        onClick={() => isClickable ? setViewingFinding(issue) : undefined}
                        className={`flex flex-col p-4 rounded-xl bg-black/40 border border-white/5 transition-colors ${isClickable ? 'cursor-pointer hover:border-[#6D5EF0]/50 hover:bg-white/5' : 'cursor-default'}`}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-3">
                            {getCategoryIcon(issue.category)}
                            <span className="font-bold text-sm text-gray-100">{issue.title}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {issue.source && issue.source.includes('CodeQL') && (
                              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border bg-purple-500/20 text-purple-400 border-purple-500/30 flex items-center gap-1">
                                <Database size={10} /> {issue.source}
                              </span>
                            )}
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getSeverityStyle(issue.severity)}`}>
                              {issue.severity ?? 'Medium'}
                            </span>
                          </div>
                        </div>

                        <div className="text-sm text-gray-400 pl-7 leading-relaxed">
                          {maskSecret(issue.description ?? '')}
                        </div>

                        {issue.file && (
                          <div className="mt-3 pl-7 flex gap-2 items-center flex-wrap">
                            <span className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-xs text-gray-400 font-mono flex items-center gap-1.5">
                              <File size={10} className="text-[#6D5EF0]" /> {issue.file}
                            </span>
                            {issue.line && (
                              <span className="text-[10px] text-gray-500 font-mono">line {issue.line}</span>
                            )}
                            <span className="text-[10px] text-[#6D5EF0] ml-auto font-medium">View source →</span>
                            {issue.autofix_available && (
                              <button
                                id={`fix-btn-${i}`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setPatchData(null);
                                  setPatchError(null);
                                  setPatchExplanation(null);
                                  setFixFinding(issue);
                                  setPatchLoading(true);
                                  fetch(`${API_BASE}/repair`, {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ session_id: sessionId, finding: issue }),
                                  })
                                    .then(r => r.json())
                                    .then(data => {
                                      if (data.explanation) setPatchExplanation(data.explanation);
                                      if (data.patch) setPatchData(data.patch);
                                      else if (data.validation_error) setPatchError(data.validation_error);
                                      else if (data.detail && data.detail.error) setPatchError(data.detail.error.message);
                                      else if (data.error && data.error.message) setPatchError(data.error.message);
                                      else if (!data.explanation) setPatchError('No patch available.');
                                    })
                                    .catch(() => setPatchError('Request failed.'))
                                    .finally(() => setPatchLoading(false));
                                }}
                                className="flex items-center gap-1.5 text-[10px] font-bold px-2.5 py-1 rounded-full bg-[#10B981]/10 border border-[#10B981]/30 text-[#10B981] hover:bg-[#10B981]/20 transition-colors"
                              >
                                <Zap size={10} /> Suggested Fix
                              </button>
                            )}
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </div>
            </div>

            {/* Phase 5: Suggested Fix Modal */}
            <AnimatePresence>
              {fixFinding && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
                  onClick={() => { setFixFinding(null); setPatchData(null); setPatchError(null); setPatchExplanation(null); }}
                >
                  <motion.div
                    initial={{ scale: 0.95, y: 20 }}
                    animate={{ scale: 1, y: 0 }}
                    exit={{ scale: 0.95, y: 20 }}
                    className="bg-[#0B0C10] border border-white/10 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[80vh] flex flex-col"
                    onClick={e => e.stopPropagation()}
                  >
                    <div className="p-5 border-b border-white/10 flex items-center justify-between">
                      <h3 className="font-bold text-white flex items-center gap-2">
                        <Zap size={16} className="text-[#10B981]" /> Suggested Fix
                        <span className="text-xs font-normal text-gray-400 ml-2">— not verified, review before applying</span>
                      </h3>
                      <button onClick={() => { setFixFinding(null); setPatchData(null); setPatchError(null); setPatchExplanation(null); }} className="text-gray-500 hover:text-white transition-colors text-lg leading-none">&times;</button>
                    </div>
                    <div className="p-5 flex-1 overflow-y-auto space-y-4">
                      <div className="text-sm text-gray-300 font-medium">{fixFinding.title}</div>
                      {patchLoading && <div className="text-sm text-gray-400 animate-pulse">Generating patch…</div>}
                      {patchError && !patchLoading && (
                        <div className="text-sm text-amber-400 bg-amber-400/10 border border-amber-400/20 rounded-lg p-3">{patchError}</div>
                      )}
                      {patchExplanation && !patchLoading && (
                        <div className="text-sm text-gray-300 bg-white/5 border border-white/10 rounded-lg p-4">
                          {patchExplanation.split('\n').map((line, i) => <p key={i} className="mb-2 last:mb-0">{line}</p>)}
                        </div>
                      )}
                      {patchData && !patchLoading && (
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="text-xs text-gray-500 font-mono">{patchData.file} — line {patchData.start_line}</div>
                            {patchData.repair_method && (
                              <span className="text-[10px] font-semibold px-2.5 py-0.5 rounded-full bg-[#6D5EF0]/20 border border-[#6D5EF0]/40 text-[#A78BFA]">
                                {patchData.repair_method === 'rule_based' && 'Method 1: Rule-Based'}
                                {patchData.repair_method === 'template_based' && 'Method 2: Template-Based'}
                                {patchData.repair_method === 'llm_based' && 'Method 3: LLM-Based'}
                                {patchData.repair_method === 'context_aware_hybrid' && 'Method 4: Context-Aware Hybrid'}
                              </span>
                            )}
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div>
                              <div className="text-[10px] uppercase tracking-wider font-bold text-red-400 mb-1">Before</div>
                              <pre className="text-xs bg-red-900/10 border border-red-500/20 rounded-lg p-3 overflow-x-auto text-red-300 whitespace-pre-wrap">{patchData.old_text}</pre>
                            </div>
                            <div>
                              <div className="text-[10px] uppercase tracking-wider font-bold text-green-400 mb-1">After</div>
                              <pre className="text-xs bg-green-900/10 border border-green-500/20 rounded-lg p-3 overflow-x-auto text-green-300 whitespace-pre-wrap">{patchData.new_text}</pre>
                            </div>
                          </div>
                          <div>
                            <div className="text-[10px] uppercase tracking-wider font-bold text-gray-500 mb-1">Unified Diff</div>
                            <pre className="text-xs bg-black/40 border border-white/5 rounded-lg p-3 overflow-x-auto text-gray-300 whitespace-pre-wrap font-mono">{patchData.diff}</pre>
                          </div>
                          {patchData.verification_details ? (
                            <div className="flex flex-col gap-2 text-[11px] text-gray-300 bg-black/40 border border-white/5 rounded-lg p-3">
                              <div className="font-bold text-gray-400 uppercase tracking-wider mb-1 text-[10px]">Sandbox Verification Result</div>
                              
                              <div className="flex items-center gap-2">
                                {patchData.verification_details.parse_result ? <CheckCircle2 size={12} className="text-[#10B981]" /> : <XCircle size={12} className="text-red-400" />}
                                <span>Parse verification: {patchData.verification_details.parse_result ? "Passed" : "Failed"}</span>
                              </div>
                              
                              {patchData.verification_details.static_result !== null && (
                                <div className="flex items-center gap-2">
                                  {patchData.verification_details.static_result ? <CheckCircle2 size={12} className="text-[#10B981]" /> : <XCircle size={12} className="text-red-400" />}
                                  <span>Static verification: {patchData.verification_details.static_result ? "Passed" : "Failed"}</span>
                                </div>
                              )}

                              {patchData.verification_details.security_result !== null && (
                                <div className="flex items-center gap-2">
                                  {patchData.verification_details.security_result ? <CheckCircle2 size={12} className="text-[#10B981]" /> : <XCircle size={12} className="text-red-400" />}
                                  <span>Security verification: {patchData.verification_details.security_result ? "Passed" : "Failed"}</span>
                                </div>
                              )}
                              
                              <div className="flex items-center gap-2">
                                {patchData.verification_details.test_result === true ? <CheckCircle2 size={12} className="text-[#10B981]" /> : 
                                 patchData.verification_details.test_result === false ? <XCircle size={12} className="text-red-400" /> :
                                 <AlertCircle size={12} className="text-amber-400" />}
                                <span>Tests: {patchData.verification_details.test_result === true ? "Passed" : patchData.verification_details.test_result === false ? "Failed" : "Not available"}</span>
                              </div>
                              
                              <div className={`mt-2 pt-2 border-t border-white/10 flex items-center gap-2 font-medium ${patchData.verification_details.status === 'PASS' ? 'text-[#10B981]' : patchData.verification_details.status === 'NOT_AVAILABLE' ? 'text-amber-400' : 'text-red-400'}`}>
                                Overall status: {patchData.verification_details.status}
                                {patchData.verification_details.message && <span className="text-gray-500 font-normal ml-1">— {patchData.verification_details.message}</span>}
                              </div>
                            </div>
                          ) : (
                            <div className="flex items-center gap-2 text-[10px] text-amber-400 bg-amber-400/5 border border-amber-400/10 rounded-lg p-2">
                              <Lock size={10} /> verification_status: {patchData.verification_status} — patch is a candidate only. Do not apply without review.
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  </motion.div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Architecture Preview */}
            <div id="architecture" className="w-full xl:w-80 bg-[#0B0C10]/60 backdrop-blur-xl border border-white/10 rounded-2xl flex flex-col shadow-xl overflow-hidden h-[500px] shrink-0">
              <div className="p-5 border-b border-white/10 flex items-center justify-between bg-black/20">
                <h3 className="font-bold flex items-center gap-2 text-white">
                  <Network size={16} className="text-[#6D5EF0]" />
                  Architecture Preview
                </h3>
              </div>

              {/* Static Graph Preview Portal */}
              <div
                className="h-48 bg-[#05050A] border-b border-white/5 relative overflow-hidden group cursor-pointer"
                onClick={() => setShowGraph(true)}
              >
                <div className="absolute inset-0 z-0 opacity-50 blur-[1px]">
                  <DependencyGraphBackground />
                </div>
                <div className="absolute inset-0 bg-black/20 group-hover:bg-black/10 transition-all z-10 flex items-center justify-center">
                  <span className="bg-black/60 text-white backdrop-blur-md px-3 py-1.5 rounded-lg text-xs font-semibold border border-white/10 opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-2">
                    <Network size={14} /> Expand Full Graph
                  </span>
                </div>
              </div>

              {/* Tree View */}
              <div className="p-5 flex-1 font-mono text-xs overflow-auto bg-transparent">
                <div className="text-[10px] uppercase tracking-wider font-bold text-gray-500 mb-3">Project File Tree</div>
                {tree.length === 0 && (
                  <div className="text-gray-600">No files detected.</div>
                )}
                {tree.map((node: string, i: number) => (
                  <div key={i} className="whitespace-pre text-gray-400 hover:text-[#6D5EF0] transition-colors cursor-default py-0.5">
                    {node}
                  </div>
                ))}
              </div>
            </div>
          </motion.div>

        </div>
      </div>
    </div>
  );
};
