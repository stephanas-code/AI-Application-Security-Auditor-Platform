import React from 'react';

interface MgSecuraLogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showText?: boolean;
  showSubtitle?: boolean;
}

export const MgSecuraLogo: React.FC<MgSecuraLogoProps> = ({
  className = '',
  size = 'md',
  showText = true,
  showSubtitle = true
}) => {
  const iconSizes = {
    sm: 'h-7 w-7',
    md: 'h-9 w-9',
    lg: 'h-12 w-12',
    xl: 'h-16 w-16'
  };

  const titleSizes = {
    sm: 'text-xs',
    md: 'text-sm',
    lg: 'text-lg',
    xl: 'text-2xl'
  };

  return (
    <div className={`flex items-center space-x-2.5 select-none ${className}`}>
      {/* High-Tech Shield Emblem */}
      <div className={`${iconSizes[size]} relative shrink-0 flex items-center justify-center rounded-xl bg-gradient-to-br from-[#121217] via-[#0D0D11] to-[#08080A] border border-[#2A2A38] shadow-lg group`}>
        <svg
          viewBox="0 0 128 128"
          className="w-full h-full p-1 drop-shadow-[0_0_8px_rgba(255,59,48,0.4)]"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="shieldCrimsonReact" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#FF3B30" />
              <stop offset="60%" stop-color="#E11D48" />
              <stop offset="100%" stop-color="#9F1239" />
            </linearGradient>
            <linearGradient id="cyberCyanReact" x1="0%" y1="100%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="#2563EB" />
              <stop offset="60%" stop-color="#38BDF8" />
              <stop offset="100%" stop-color="#60A5FA" />
            </linearGradient>
          </defs>

          {/* Shield Outer Silhouette */}
          <path
            d="M 64,18 L 100,32 C 100,68 85,96 64,110 C 43,96 28,68 28,32 Z"
            fill="url(#shieldCrimsonReact)"
            opacity="0.22"
          />

          {/* Shield Border */}
          <path
            d="M 64,22 L 96,35 C 96,68 82,92 64,105 C 46,92 32,68 32,35 Z"
            stroke="url(#shieldCrimsonReact)"
            strokeWidth="4"
            strokeLinejoin="round"
          />

          {/* Left Wing (Facet M) */}
          <path
            d="M 42,42 L 54,42 L 64,62 L 56,76 L 46,58 L 46,84 L 38,84 Z"
            fill="url(#cyberCyanReact)"
          />

          {/* Right Wing (Facet S) */}
          <path
            d="M 86,44 L 66,44 L 60,54 L 74,54 C 80,54 84,57 84,63 C 84,70 78,74 70,74 L 62,74 L 62,84 L 72,84 C 84,84 92,76 92,64 C 92,52 86,46 86,44 Z"
            fill="#FFFFFF"
          />

          {/* Center Lightning Core */}
          <polygon points="64,30 68,52 61,52 65,70 57,55 63,55" fill="#FF3B30" />

          {/* Glowing Apex & Base Nodes */}
          <circle cx="64" cy="22" r="3" fill="#38BDF8" className="animate-pulse" />
          <circle cx="64" cy="105" r="2.5" fill="#FF3B30" />
        </svg>
      </div>

      {/* Typography: MgSecura */}
      {showText && (
        <div className="flex flex-col">
          <div className="flex items-center space-x-1.5 leading-none">
            <span className={`${titleSizes[size]} font-black tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-sky-300 to-white`}>
              Mg
            </span>
            <span className={`${titleSizes[size]} font-black tracking-tight text-white`}>
              Secura
            </span>
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-blue-950/80 text-blue-400 font-bold border border-blue-800/80 tracking-wide">
              AI 3.8
            </span>
          </div>
          {showSubtitle && (
            <p className="text-[10px] font-mono text-gray-400 tracking-wider uppercase mt-1">
              Autonomous AppSec Auditor
            </p>
          )}
        </div>
      )}
    </div>
  );
};
