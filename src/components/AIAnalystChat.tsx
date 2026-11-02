import React, { useState, useRef, useEffect } from 'react';
import { 
  X, 
  Send, 
  Sparkles, 
  Bot, 
  User, 
  Loader2,
  Key,
  CheckCircle2,
  Copy,
  Check
} from 'lucide-react';
import { ChatMessage, VulnerabilityFinding, ScanTarget } from '../types';

interface AIAnalystChatProps {
  isOpen: boolean;
  onClose: () => void;
  findings: VulnerabilityFinding[];
  currentScore: number;
  target?: ScanTarget;
}

const FormattedChatMessage: React.FC<{ text: string; isUser: boolean }> = ({ text, isUser }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleCopyCode = (code: string, idx: number) => {
    navigator.clipboard.writeText(code);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  if (isUser) {
    return <div className="whitespace-pre-wrap leading-relaxed">{text}</div>;
  }

  // Parse markdown code blocks (```lang\n...```)
  const parts: Array<{ type: 'code' | 'text'; content: string; lang?: string }> = [];
  const codeBlockRegex = /```([a-zA-Z0-9_-]*)\r?\n([\s\S]*?)```/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = codeBlockRegex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push({ type: 'text', content: text.substring(lastIndex, match.index) });
    }
    parts.push({
      type: 'code',
      lang: match[1] || 'code',
      content: match[2]?.trim() || ''
    });
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < text.length) {
    parts.push({ type: 'text', content: text.substring(lastIndex) });
  }

  const renderInlineSpans = (str: string) => {
    // Matches inline code (`code`), bold (**text**), or italic (*text*)
    const tokens = str.split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g);
    return tokens.map((token, idx) => {
      if (token.startsWith('`') && token.endsWith('`')) {
        return (
          <code key={idx} className="px-1.5 py-0.5 rounded bg-[#202020] text-emerald-300 font-mono text-[11px] border border-[#2E2E2E]">
            {token.slice(1, -1)}
          </code>
        );
      }
      if (token.startsWith('**') && token.endsWith('**')) {
        return (
          <strong key={idx} className="font-bold text-white">
            {token.slice(2, -2)}
          </strong>
        );
      }
      if (token.startsWith('*') && token.endsWith('*') && token.length > 2) {
        return (
          <em key={idx} className="italic text-gray-300">
            {token.slice(1, -1)}
          </em>
        );
      }
      return token;
    });
  };

  const renderInlineFormatted = (rawText: string) => {
    const lines = rawText.split('\n');
    return lines.map((line, lineIdx) => {
      // 1. Headers (###, ##, #)
      if (line.startsWith('### ')) {
        return (
          <h4 key={lineIdx} className="text-xs font-bold text-blue-400 mt-2.5 mb-1 tracking-wide uppercase">
            {renderInlineSpans(line.replace('### ', ''))}
          </h4>
        );
      }
      if (line.startsWith('## ')) {
        return (
          <h3 key={lineIdx} className="text-xs font-extrabold text-white mt-3 mb-1 border-b border-[#2A2A2A] pb-0.5 tracking-wide">
            {renderInlineSpans(line.replace('## ', ''))}
          </h3>
        );
      }
      if (line.startsWith('# ')) {
        return (
          <h2 key={lineIdx} className="text-sm font-black text-white mt-3 mb-1.5 tracking-wide">
            {renderInlineSpans(line.replace('# ', ''))}
          </h2>
        );
      }

      // 2. Bullet list items (*, -, •)
      if (/^\s*[-*•]\s+/.test(line)) {
        const itemText = line.replace(/^\s*[-*•]\s+/, '');
        return (
          <div key={lineIdx} className="flex items-start space-x-2 my-0.5 pl-1.5">
            <span className="text-blue-400 font-bold text-[10px] leading-5">•</span>
            <div className="flex-1 leading-relaxed text-gray-200">
              {renderInlineSpans(itemText)}
            </div>
          </div>
        );
      }

      // 3. Numbered list items (1., 2., etc)
      const numMatch = line.match(/^\s*(\d+)\.\s+(.*)/);
      if (numMatch) {
        return (
          <div key={lineIdx} className="flex items-start space-x-2 my-0.5 pl-1.5">
            <span className="text-emerald-400 font-mono font-bold text-[10px] leading-5 shrink-0">{numMatch[1]}.</span>
            <div className="flex-1 leading-relaxed text-gray-200">
              {renderInlineSpans(numMatch[2] || '')}
            </div>
          </div>
        );
      }

      // 4. Blockquotes (> text)
      if (line.startsWith('> ')) {
        return (
          <div key={lineIdx} className="pl-3 py-1 my-1 border-l-2 border-blue-500/60 bg-blue-950/20 text-gray-300 italic text-xs rounded-r">
            {renderInlineSpans(line.replace('> ', ''))}
          </div>
        );
      }

      // Empty line -> spacing
      if (!line.trim()) {
        return <div key={lineIdx} className="h-1.5" />;
      }

      // Normal paragraph line
      return (
        <p key={lineIdx} className="leading-relaxed my-0.5 text-gray-200">
          {renderInlineSpans(line)}
        </p>
      );
    });
  };

  return (
    <div className="space-y-1 text-xs">
      {parts.map((p, idx) => {
        if (p.type === 'code') {
          return (
            <div key={idx} className="my-2 rounded-xl bg-black/90 border border-[#262626] overflow-hidden shadow-lg">
              <div className="px-3 py-1.5 bg-[#181818] border-b border-[#262626] flex items-center justify-between text-[10px] font-mono text-gray-400">
                <span className="uppercase font-bold tracking-wider text-blue-400">{p.lang || 'CODE'}</span>
                <button
                  onClick={() => handleCopyCode(p.content, idx)}
                  className="flex items-center space-x-1 px-2 py-0.5 rounded bg-[#242424] hover:bg-[#303030] text-gray-300 hover:text-white transition-colors cursor-pointer"
                  title="Copy code to clipboard"
                >
                  {copiedIndex === idx ? (
                    <>
                      <Check className="h-3 w-3 text-emerald-400" />
                      <span className="text-emerald-400 font-bold">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-3 overflow-x-auto font-mono text-[11px] leading-relaxed text-emerald-300/95 scrollbar-thin">
                <code>{p.content}</code>
              </pre>
            </div>
          );
        }
        return <div key={idx}>{renderInlineFormatted(p.content)}</div>;
      })}
    </div>
  );
};

export const AIAnalystChat: React.FC<AIAnalystChatProps> = ({
  isOpen,
  onClose,
  findings,
  currentScore,
  target
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      sender: 'analyst',
      text: `MgSecura Gemini 3.8 Analyst Online. I have correlated your active scan results${target ? ` for ${target.name}` : ''} (Security Score: ${currentScore}/100, ${findings.length} finding(s)).\n\nAsk any technical questions about detected vulnerabilities, safe verification steps, or remediation patches.`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showKeySetup, setShowKeySetup] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [aiStatus, setAiStatus] = useState<{ hasValidKey: boolean; maskedKey: string; aiModel: string } | null>(null);
  const [savingKey, setSavingKey] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  useEffect(() => {
    if (isOpen) {
      fetch('/api/settings/ai-config')
        .then(r => r.json())
        .then(d => {
          if (d.success) setAiStatus(d);
        })
        .catch(() => {});
    }
  }, [isOpen]);

  const handleSaveKeyInChat = async () => {
    if (!apiKeyInput.trim()) return;
    setSavingKey(true);
    try {
      const res = await fetch('/api/settings/ai-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: apiKeyInput.trim(), aiModel: 'gemini-3.8' })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setAiStatus(data);
        setApiKeyInput('');
        setShowKeySetup(false);
      }
    } catch {} finally {
      setSavingKey(false);
    }
  };

  if (!isOpen) return null;

  const quickPrompts = findings.length > 0
    ? [
        `Explain the ${findings[0]!.title} in ${findings[0]!.file}`,
        findings[1] ? `How do I verify and fix ${findings[1].title}?` : `What are the top priority patches for ${target?.name || 'this target'}?`,
        `Summarize all ${findings.length} vulnerabilities and how they chain together`,
        `Generate a step-by-step remediation checklist for ${target?.name || 'our application'}`
      ]
    : [
        "Explain the SQL Injection in transactions.js",
        "How does the AWS credential leak affect our cloud infrastructure?",
        "What is the recommended fix for the lodash prototype pollution?",
        "How can an attacker exploit the unrestricted CORS wildcard?"
      ];

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || inputText;
    if (!query.trim() || isLoading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    setInputText('');
    setIsLoading(true);

    try {
      const response = await fetch('/api/ai-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: query,
          targetContext: target
            ? { name: target.name, platform: target.platform, language: target.language }
            : undefined,
          findingsContext: findings.slice(0, 20).map(f => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            category: f.category,
            file: f.file,
            line: f.line,
            cwe: f.cwe,
            status: f.status,
            codeSnippet: f.codeSnippet,
            rootCause: f.rootCause,
            recommendation: f.recommendation,
            proposedPatch: f.proposedPatch
              ? { afterCode: f.proposedPatch.afterCode, explanation: f.proposedPatch.explanation }
              : undefined
          })),
          currentScore,
          preferredModel: 'gemini-3.8'
        })
      });

      const data = await response.json();

      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        sender: 'analyst',
        text: data.reply || "I analyzed your request. Please review the recommended patches in the Remediation Hub.",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setMessages(prev => [...prev, aiMsg]);
    } catch (err: any) {
      setMessages(prev => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          sender: 'analyst',
          text: "I encountered an issue connecting to the AI analysis engine. You can still apply automated patches directly in the Audit Dashboard.",
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md bg-[#111111] border-l border-[#1F1F1F] shadow-2xl flex flex-col animate-in slide-in-from-right duration-200">
      
      {/* Drawer Header */}
      <div className="px-5 py-3.5 border-b border-[#1F1F1F] bg-[#161616] space-y-2.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse"></div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-xs font-bold uppercase tracking-widest text-white">
                  MgSecura AI Analyst
                </h3>
                <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-blue-950 text-blue-400 border border-blue-800">
                  Gemini 3.8
                </span>
              </div>
              <p className="text-[10px] text-gray-500">Interactive threat modeling & code remediation</p>
            </div>
          </div>

          <div className="flex items-center space-x-1.5">
            <button
              onClick={() => setShowKeySetup(prev => !prev)}
              className={`flex items-center space-x-1 px-2 py-1 rounded-lg text-[10px] font-mono border transition-colors cursor-pointer ${
                aiStatus?.hasValidKey
                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                  : 'bg-amber-950/60 text-amber-300 border-amber-800/60'
              }`}
              title="Configure Gemini 3.8 API Key"
            >
              <Key className="h-3 w-3" />
              <span>{aiStatus?.hasValidKey ? 'Key Active' : 'Set API Key'}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-[#1F1F1F] transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {showKeySetup && (
          <div className="p-2.5 rounded-xl bg-black/80 border border-blue-900/60 space-y-2">
            <div className="flex items-center justify-between text-[10px] font-mono text-gray-300">
              <span>Gemini 3.8 API Key:</span>
              {aiStatus?.hasValidKey && (
                <span className="text-emerald-400 flex items-center space-x-1">
                  <CheckCircle2 className="h-3 w-3" />
                  <span>{aiStatus.maskedKey}</span>
                </span>
              )}
            </div>
            <div className="flex items-center space-x-1.5">
              <input
                type="password"
                value={apiKeyInput}
                onChange={(e) => setApiKeyInput(e.target.value)}
                placeholder="Paste GEMINI_API_KEY (AIzaSy...)..."
                className="flex-1 px-2.5 py-1.5 bg-[#111111] border border-[#2A2A2A] rounded-lg text-xs font-mono text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={handleSaveKeyInChat}
                disabled={savingKey || !apiKeyInput.trim()}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-[10px] font-bold uppercase cursor-pointer"
              >
                {savingKey ? '...' : 'Save'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Chat Messages */}
      <div className="flex-1 p-4 overflow-y-auto space-y-3.5 bg-[#0A0A0A] font-sans text-xs">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex items-start space-x-2.5 ${
              msg.sender === 'user' ? 'flex-row-reverse space-x-reverse' : ''
            }`}
          >
            <div className={`h-7 w-7 rounded-lg flex items-center justify-center flex-shrink-0 text-xs font-bold ${
              msg.sender === 'user' 
                ? 'bg-blue-600 text-white' 
                : 'bg-[#1A1A1A] border border-[#333333] text-blue-400'
            }`}>
              {msg.sender === 'user' ? <User className="h-3.5 w-3.5" /> : <Bot className="h-3.5 w-3.5" />}
            </div>

            <div className={`max-w-[85%] rounded-xl p-3 leading-relaxed ${
              msg.sender === 'user'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'bg-[#161616] border border-[#1F1F1F] text-gray-200 shadow-md'
            }`}>
              <FormattedChatMessage text={msg.text} isUser={msg.sender === 'user'} />
              <div className={`text-[9px] mt-2 font-mono ${
                msg.sender === 'user' ? 'text-blue-200' : 'text-gray-600'
              }`}>
                {msg.timestamp}
              </div>
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex items-center space-x-2 text-gray-400 p-2 text-xs">
            <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
            <span>AI Analyst is reasoning through threat model...</span>
          </div>
        )}
        <div ref={scrollRef} />
      </div>

      {/* Quick Prompts */}
      <div className="p-3 border-t border-[#1F1F1F] bg-[#141414] space-y-1.5">
        <span className="text-[9px] font-mono uppercase tracking-wider text-gray-500 font-bold">Suggested Questions:</span>
        <div className="flex flex-wrap gap-1.5">
          {quickPrompts.map((prompt, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(prompt)}
              className="px-2.5 py-1 bg-[#1A1A1A] hover:bg-[#222222] border border-[#333333] text-[10px] text-gray-300 hover:text-white rounded-md transition-colors text-left truncate max-w-full"
            >
              {prompt}
            </button>
          ))}
        </div>
      </div>

      {/* Input Box */}
      <div className="p-3 border-t border-[#1F1F1F] bg-[#161616] flex items-center space-x-2">
        <input
          type="text"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
          placeholder="Ask a security or remediation question..."
          className="flex-1 px-3 py-2 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white placeholder-gray-500 focus:outline-none focus:border-[#333333]"
        />
        <button
          onClick={() => handleSendMessage()}
          disabled={isLoading || !inputText.trim()}
          className="p-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl transition-colors disabled:opacity-50"
        >
          <Send className="h-4 w-4" />
        </button>
      </div>

    </div>
  );
};
