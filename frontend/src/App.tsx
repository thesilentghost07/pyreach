import React, { useState } from 'react';
import ScanSetup from './components/ScanSetup';
import './index.css';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'upload' | 'results'>('upload');
  const [currentPath, setCurrentPath] = useState('tests/fixtures/reachable_app');
  const [scanResult, setScanResult] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleScan = async (path: string) => {
    setIsLoading(true);
    setCurrentPath(path);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_path: path, use_network: false })
      });
      if (res.ok) {
        const data = await res.json();
        setScanResult(data);
        setActiveTab('results');
      }
    } catch (err) {
      console.warn('API error, check if backend is running on 8000', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', position: 'relative' }}>
      {/* 1. Subtle White Transparent Grid Background With Ambient Drift */}
      <div className="bg-grid-layer" aria-hidden="true" />

      {/* Header */}
      <header style={{
        height: '60px',
        background: 'rgba(5, 5, 7, 0.82)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.07)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 24px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '28px',
            height: '28px',
            background: '#121218',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            🛡️
          </div>
          <span style={{ fontWeight: 700, fontSize: '17px', color: '#f8fafc' }}>PyReach</span>
          <span style={{
            fontSize: '11px',
            color: '#a1a1aa',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            padding: '2px 8px',
            borderRadius: '999px'
          }}>
            Static Reachability Analyzer
          </span>
        </div>

        <nav style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => setActiveTab('upload')}
            style={{
              background: activeTab === 'upload' ? '#f4f4f6' : 'transparent',
              color: activeTab === 'upload' ? '#09090b' : '#a1a1aa',
              border: 'none',
              borderRadius: '8px',
              padding: '6px 14px',
              fontWeight: 600,
              fontSize: '12px',
              cursor: 'pointer'
            }}
          >
            Scan Setup
          </button>
          <button
            onClick={() => setActiveTab('results')}
            style={{
              background: activeTab === 'results' ? '#f4f4f6' : 'transparent',
              color: activeTab === 'results' ? '#09090b' : '#a1a1aa',
              border: 'none',
              borderRadius: '8px',
              padding: '6px 14px',
              fontWeight: 600,
              fontSize: '12px',
              cursor: 'pointer'
            }}
          >
            Findings
          </button>
        </nav>
      </header>

      {/* Main Content Area */}
      <main style={{ padding: '40px 20px', position: 'relative', zIndex: 10 }}>
        {activeTab === 'upload' ? (
          <div style={{ textAlign: 'center' }}>
            <h1 style={{
              fontSize: '36px',
              fontWeight: 700,
              letterSpacing: '-0.03em',
              background: 'linear-gradient(180deg, #ffffff 0%, #a1a1aa 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              margin: '0 0 8px 0'
            }}>
              Scan Python Repository
            </h1>
            <p style={{ color: '#71717a', fontSize: '14.5px', marginBottom: '32px' }}>
              Deterministic reachability analysis across Python AST call graphs with zero code execution.
            </p>

            <ScanSetup onScan={handleScan} isLoading={isLoading} />
          </div>
        ) : (
          <div style={{ maxWidth: '980px', margin: '0 auto' }}>
            <h2 style={{ fontSize: '22px', fontWeight: 700, color: '#f8fafc' }}>
              Scan Findings for {currentPath}
            </h2>
            {scanResult ? (
              <pre style={{
                background: '#0a0a0e',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                padding: '20px',
                borderRadius: '12px',
                overflowX: 'auto',
                color: '#4ade80'
              }}>
                {JSON.stringify(scanResult, null, 2)}
              </pre>
            ) : (
              <p style={{ color: '#71717a' }}>No scan executed yet. Run a scan from the Scan Setup tab.</p>
            )}
          </div>
        )}
      </main>
    </div>
  );
};

export default App;
