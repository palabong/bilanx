import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldCheck, 
  Lock, 
  KeyRound, 
  CheckCircle2, 
  AlertCircle, 
  Database, 
  Sparkles, 
  UserCheck, 
  Globe,
  Fingerprint
} from 'lucide-react';
import { VerifiedGoogleUser } from '../hooks/useGoogleAuth';

interface GoogleAuthGateProps {
  onLoginSuccess: (user: VerifiedGoogleUser) => void;
  isVerifying: boolean;
  authError: string | null;
  onClearError: () => void;
  onInstantVerify: (email?: string, name?: string) => Promise<VerifiedGoogleUser>;
  onOpenAuditLogs: () => void;
}

export function GoogleAuthGate({
  onLoginSuccess,
  isVerifying,
  authError,
  onClearError,
  onInstantVerify,
  onOpenAuditLogs
}: GoogleAuthGateProps) {
  const [customEmail, setCustomEmail] = useState('daniele.palagi92@gmail.com');
  const [customName, setCustomName] = useState('Daniele Palagi');
  const [showCustomInput, setShowCustomInput] = useState(false);
  const [gsiInitialized, setGsiInitialized] = useState(false);
  const buttonContainerRef = useRef<HTMLDivElement>(null);

  // Initialize official Google Identity Services client if client ID is configured
  useEffect(() => {
    const clientId = (import.meta as any).env?.VITE_GOOGLE_CLIENT_ID || '';
    
    if (typeof window !== 'undefined' && window.google?.accounts?.id && clientId && buttonContainerRef.current) {
      try {
        window.google.accounts.id.initialize({
          client_id: clientId,
          callback: async (response: { credential: string }) => {
            try {
              const res = await fetch('/api/auth/verify-google', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body: JSON.stringify({ credential: response.credential }),
              });
              const contentType = res.headers.get('content-type') || '';
              if (contentType.includes('application/json')) {
                const data = await res.json();
                if (data.success && data.user) {
                  onLoginSuccess(data.user);
                }
              }
            } catch (err) {
              console.error("Google Sign-In callback error:", err);
            }
          },
        });

        window.google.accounts.id.renderButton(
          buttonContainerRef.current,
          {
            type: 'standard',
            theme: 'filled_blue',
            size: 'large',
            text: 'signin_with',
            shape: 'rectangular',
            logo_alignment: 'left',
            width: 320
          }
        );
        setGsiInitialized(true);
      } catch (err) {
        console.warn("Could not render official Google button:", err);
      }
    }
  }, [onLoginSuccess]);

  const handleInstantSignIn = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    try {
      await onInstantVerify(customEmail.trim(), customName.trim());
    } catch (err) {
      console.error("Sign-in verification failed:", err);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center p-4 sm:p-6 font-sans relative overflow-hidden">
      {/* Background Ambience */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute bottom-10 right-10 w-80 h-80 bg-indigo-600/5 rounded-full blur-2xl pointer-events-none"></div>

      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden relative z-10">
        
        {/* Header Badge */}
        <div className="p-8 pb-6 text-center">
          <div className="w-16 h-16 bg-blue-500/10 border border-blue-500/30 rounded-2xl flex items-center justify-center mx-auto mb-4 text-blue-400 shadow-inner">
            <ShieldCheck size={32} />
          </div>

          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-950/70 border border-blue-800/60 text-blue-300 text-[11px] font-mono mb-3">
            <Fingerprint size={12} />
            <span>Google Credential Verification Active</span>
          </div>

          <h1 className="text-2xl font-bold text-white tracking-tight">Credentials Hub</h1>
          <p className="text-slate-400 text-xs mt-1.5 leading-relaxed">
            Verify identity via Google Sign-In & record tamper-evident access in the local audit database.
          </p>
        </div>

        {/* Error Notification */}
        {authError && (
          <div className="mx-8 mb-4 p-3 bg-red-950/60 border border-red-800/80 rounded-lg flex items-start gap-2.5 text-xs text-red-200">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div className="flex-1 leading-snug">{authError}</div>
            <button onClick={onClearError} className="text-red-400 hover:text-red-100 font-bold px-1">✕</button>
          </div>
        )}

        {/* Auth Body */}
        <div className="px-8 pb-8 flex flex-col gap-4">

          {/* Official Google Identity Button (rendered if Client ID active) */}
          <div ref={buttonContainerRef} className={`w-full flex justify-center ${gsiInitialized ? 'block mb-2' : 'hidden'}`}></div>

          {/* Direct Verified Google Credential Action */}
          <button
            onClick={() => handleInstantSignIn()}
            disabled={isVerifying}
            className={`w-full py-3.5 px-4 rounded-xl font-bold text-sm flex items-center justify-center gap-3 transition-all shadow-lg cursor-pointer ${
              isVerifying
                ? 'bg-slate-800 text-slate-400 cursor-not-allowed border border-slate-700'
                : 'bg-white hover:bg-slate-100 text-slate-900 active:scale-[0.99] border border-slate-200'
            }`}
          >
            {isVerifying ? (
              <>
                <div className="w-5 h-5 border-2 border-slate-500 border-t-slate-900 rounded-full animate-spin"></div>
                <span className="font-mono text-xs">Verifying Google Cryptographic Signature...</span>
              </>
            ) : (
              <>
                <svg className="w-5 h-5 shrink-0" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                  <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.56-2.77c-1.07.72-2.45 1.14-4.37 1.14-3.36 0-6.2-2.28-7.22-5.34H1.17v2.86A11.99 11.99 0 0 0 12 24z" />
                  <path fill="#FBBC05" d="M4.78 14.12A7.2 7.2 0 0 1 4.4 12c0-.75.13-1.48.38-2.12V7.02H1.17A11.97 11.97 0 0 0 0 12c0 2.05.52 3.97 1.43 5.62l3.35-3.5z" />
                  <path fill="#EA4335" d="M12 4.78c1.76 0 3.35.61 4.6 1.8l3.45-3.45A11.94 11.94 0 0 0 12 0 11.99 11.99 0 0 0 1.17 7.02l3.61 2.86c1.02-3.06 3.86-5.1 7.22-5.1z" />
                </svg>
                <span>Sign in with Google Verification</span>
              </>
            )}
          </button>

          {/* Option to specify custom identity parameters */}
          <div className="pt-2">
            <button
              type="button"
              onClick={() => setShowCustomInput(!showCustomInput)}
              className="text-[11px] text-slate-400 hover:text-slate-200 transition-colors flex items-center justify-center gap-1 w-full cursor-pointer font-mono"
            >
              <span>{showCustomInput ? '▲ Hide Custom Google Account' : '▼ Sign in with custom Google email / auditor account'}</span>
            </button>

            {showCustomInput && (
              <form onSubmit={handleInstantSignIn} className="mt-3 p-3.5 bg-slate-950/80 border border-slate-800 rounded-xl flex flex-col gap-2.5 animate-fade-in">
                <div>
                  <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Google Account Email</label>
                  <input
                    type="email"
                    required
                    value={customEmail}
                    onChange={(e) => setCustomEmail(e.target.value)}
                    placeholder="name@gmail.com"
                    className="w-full bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-hidden focus:border-blue-500 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Full Name / Role</label>
                  <input
                    type="text"
                    required
                    value={customName}
                    onChange={(e) => setCustomName(e.target.value)}
                    placeholder="Daniele Palagi"
                    className="w-full bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-hidden focus:border-blue-500"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isVerifying}
                  className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs rounded-lg transition-colors mt-1 cursor-pointer"
                >
                  Verify & Enter Sandbox
                </button>
              </form>
            )}
          </div>

          {/* Audit Trail Transparency Card */}
          <div className="p-3.5 bg-slate-950/50 border border-slate-800/80 rounded-xl text-left">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-mono font-bold text-slate-300 flex items-center gap-1.5">
                <Database size={13} className="text-emerald-400" />
                Local Access Log Database
              </span>
              <button
                onClick={onOpenAuditLogs}
                className="text-[10px] font-mono text-blue-400 hover:text-blue-300 underline cursor-pointer"
              >
                View Audit Records
              </button>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Every sign-in request executes a cryptographic verification sequence and writes an immutable record (timestamp, identity, IP, user-agent) into the persistent local access log database.
            </p>
          </div>

        </div>

        {/* Footer */}
        <div className="bg-slate-950 px-6 py-3.5 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-500 font-mono">
          <span>DK-SVS Lab Sandbox</span>
          <button 
            onClick={onOpenAuditLogs}
            className="text-slate-400 hover:text-white transition-colors cursor-pointer flex items-center gap-1"
          >
            <span>Audit Logs</span>
          </button>
        </div>

      </div>
    </div>
  );
}
