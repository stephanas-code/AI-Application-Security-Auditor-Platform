import React, { useState, useRef, useEffect } from 'react';
import { 
  X, 
  Send, 
  Sparkles, 
  Bot, 
  User, 
  Loader2
} from 'lucide-react';
import { ChatMessage, VulnerabilityFinding } from '../types';

interface AIAnalystChatProps {
  isOpen: boolean;
  onClose: () => void;
  findings: VulnerabilityFinding[];
  currentScore: number;
}

export const AIAnalystChat: React.FC<AIAnalystChatProps> = ({
  isOpen,
  onClose,
  findings,
  currentScore
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      sender: 'analyst',
      text: `SHIELD.AI Analyst Online. I have correlated your active scan results (Security Score: ${currentScore}/100).\n\nAsk any technical questions about attack scenarios, code fixes, or compliance requirements.`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  if (!isOpen) return null;

  const quickPrompts = [
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
          findingsContext: findings.map(f => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            category: f.category,
            file: f.file,
            line: f.line,
            cwe: f.cwe,
            status: f.status
          })),
          currentScore
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
      <div className="px-5 py-4 border-b border-[#1F1F1F] bg-[#161616] flex items-center justify-between">
        <div className="flex items-center space-x-2.5">
          <div className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse"></div>
          <div>
            <h3 className="text-xs font-bold uppercase tracking-widest text-white">
              SHIELD.AI Analyst
            </h3>
            <p className="text-[10px] text-gray-500">Interactive threat modeling & code remediation</p>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-[#1F1F1F] transition-colors"
        >
          <X className="h-5 w-5" />
        </button>
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

            <div className={`max-w-[82%] rounded-xl p-3 leading-relaxed ${
              msg.sender === 'user'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'bg-[#161616] border border-[#1F1F1F] text-gray-200 shadow-md'
            }`}>
              <div className="whitespace-pre-wrap">{msg.text}</div>
              <div className={`text-[9px] mt-1.5 font-mono ${
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
