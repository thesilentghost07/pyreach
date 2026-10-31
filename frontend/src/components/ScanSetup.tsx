import React, { useState, useRef, MouseEvent, DragEvent } from 'react';

interface ScanSetupProps {
  onScan: (projectPath: string) => void;
  isLoading?: boolean;
}

export const ScanSetup: React.FC<ScanSetupProps> = ({ onScan, isLoading = false }) => {
  const [projectPath, setProjectPath] = useState('tests/fixtures/reachable_app');
  const [isDragOver, setIsDragOver] = useState(false);
  const dropzoneRef = useRef<HTMLDivElement>(null);

  // Mouse-tracking spotlight: update CSS variables --mouse-x and --mouse-y
  const handleMouseMove = (e: MouseEvent<HTMLDivElement>) => {
    if (!dropzoneRef.current) return;
    const rect = dropzoneRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    dropzoneRef.current.style.setProperty('--mouse-x', `${x}px`);
    dropzoneRef.current.style.setProperty('--mouse-y', `${y}px`);
  };

  const handleMouseLeave = () => {
    if (!dropzoneRef.current) return;
    dropzoneRef.current.style.removeProperty('--mouse-x');
    dropzoneRef.current.style.removeProperty('--mouse-y');
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(true);
    if (!dropzoneRef.current) return;
    const rect = dropzoneRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    dropzoneRef.current.style.setProperty('--mouse-x', `${x}px`);
    dropzoneRef.current.style.setProperty('--mouse-y', `${y}px`);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      setProjectPath(file.name);
      onScan(file.name);
    }
  };

  const handlePresetSelect = (path: string) => {
    setProjectPath(path);
    onScan(path);
  };

  return (
    <div style={{
      maxWidth: '980px',
      width: '100%',
      margin: '0 auto',
      borderRadius: '18px',
      background: 'rgba(10, 10, 14, 0.82)',
      border: '1px solid rgba(255, 255, 255, 0.08)',
      padding: '28px',
      boxShadow: 'inset 0 1px 0 rgba(255, 255, 255, 0.06), 0 20px 40px rgba(0,0,0,0.6)',
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)'
    }}>
      {/* Interactive Dropzone Rectangle with 32px Grid, Mouse-Tracking Spotlight, and Corner Brackets */}
      <div
        ref={dropzoneRef}
        id="dropzone"
        className={`dropzone-beam-container group ${isDragOver ? 'drag-over' : ''}`}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        style={{
          padding: '44px 24px',
          textAlign: 'center',
          position: 'relative',
          cursor: 'pointer'
        }}
      >
        {/* Subtle White Transparent Grid Overlay */}
        <div className="dropzone-grid-layer" aria-hidden="true" />

        {/* Mouse-Tracking Spotlight Overlay */}
        <div className="dropzone-spotlight" aria-hidden="true" />

        {/* Sleek 4 Corner Brackets */}
        <span className="corner-bracket corner-tl" aria-hidden="true" />
        <span className="corner-bracket corner-tr" aria-hidden="true" />
        <span className="corner-bracket corner-bl" aria-hidden="true" />
        <span className="corner-bracket corner-br" aria-hidden="true" />

        {/* Animated Upload Icon */}
        <svg
          className="dropzone-upload-icon"
          xmlns="http://www.w3.org/2000/svg"
          width="38"
          height="38"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{
            color: '#71717a',
            margin: '0 auto 14px',
            position: 'relative',
            zIndex: 3
          }}
          aria-hidden="true"
        >
          <path d="M12 13v8" />
          <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242" />
          <path d="m8 17 4-4 4 4" />
        </svg>

        <h3 style={{
          fontSize: '16px',
          fontWeight: 600,
          color: '#f4f4f6',
          marginBottom: '6px',
          position: 'relative',
          zIndex: 3
        }}>
          Drag and drop your repository folder or .zip archive
        </h3>
        <p style={{
          fontSize: '13px',
          color: '#71717a',
          margin: '0 auto 20px',
          maxWidth: '480px',
          position: 'relative',
          zIndex: 3
        }}>
          Client-side filters automatically skip <code>.venv</code>, <code>venv</code>, and <code>node_modules</code>.
        </p>

        {/* Buttons inside dropzone */}
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          gap: '12px',
          flexWrap: 'wrap',
          position: 'relative',
          zIndex: 3
        }}>
          <button
            type="button"
            style={{
              background: '#121218',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              color: '#f4f4f6',
              borderRadius: '8px',
              padding: '8px 16px',
              fontSize: '12.5px',
              fontWeight: 500,
              cursor: 'pointer'
            }}
          >
            Choose .ZIP Archive
          </button>
          <button
            type="button"
            style={{
              background: '#121218',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              color: '#f4f4f6',
              borderRadius: '8px',
              padding: '8px 16px',
              fontSize: '12.5px',
              fontWeight: 500,
              cursor: 'pointer'
            }}
          >
            Choose Repository Folder
          </button>
        </div>
      </div>

      {/* Quick Evaluation Presets */}
      <div style={{ marginTop: '26px' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '12px'
        }}>
          <span style={{ fontSize: '11.5px', fontWeight: 700, letterSpacing: '0.08em', color: '#d4d4d8' }}>
            ⚡ QUICK EVALUATION PRESETS
          </span>
          <span style={{ fontSize: '11.5px', color: '#71717a', fontFamily: 'var(--font-mono)' }}>
            1-Click Auto-Fill & Immediate Scan
          </span>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '12px'
        }}>
          <div
            onClick={() => handlePresetSelect('tests/fixtures/reachable_app')}
            style={{
              padding: '14px 16px',
              background: '#09090e',
              border: '1px solid rgba(225, 29, 72, 0.25)',
              borderRadius: '10px',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 700, color: '#fb7185', fontSize: '13px' }}>🔴 Reachable App</span>
              <span style={{ fontSize: '11px', color: '#71717a' }}>pyyaml 5.3.1</span>
            </div>
            <p style={{ fontSize: '12px', color: '#a1a1aa', margin: '4px 0 0 0' }}>
              Confirmed call path to <code>yaml.load</code>
            </p>
          </div>

          <div
            onClick={() => handlePresetSelect('tests/fixtures/not_reachable_app')}
            style={{
              padding: '14px 16px',
              background: '#09090e',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              borderRadius: '10px',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 700, color: '#4ade80', fontSize: '13px' }}>🟢 Safe / Not Reachable</span>
              <span style={{ fontSize: '11px', color: '#71717a' }}>pyyaml 5.3.1</span>
            </div>
            <p style={{ fontSize: '12px', color: '#a1a1aa', margin: '4px 0 0 0' }}>
              Only calls safe <code>yaml.safe_load</code>
            </p>
          </div>

          <div
            onClick={() => handlePresetSelect('tests/fixtures/uncertain_app')}
            style={{
              padding: '14px 16px',
              background: '#09090e',
              border: '1px solid rgba(217, 119, 6, 0.25)',
              borderRadius: '10px',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 700, color: '#fbbf24', fontSize: '13px' }}>🟡 Uncertain / Hazard</span>
              <span style={{ fontSize: '11px', color: '#71717a' }}>pyyaml 5.3.1</span>
            </div>
            <p style={{ fontSize: '12px', color: '#a1a1aa', margin: '4px 0 0 0' }}>
              Dynamic reflection via <code>getattr()</code>
            </p>
          </div>
        </div>
      </div>

      {/* Manual Path Input Row */}
      <div style={{
        marginTop: '20px',
        display: 'flex',
        gap: '10px',
        alignItems: 'center'
      }}>
        <input
          type="text"
          value={projectPath}
          onChange={(e) => setProjectPath(e.target.value)}
          placeholder="Path to Python project (e.g., tests/fixtures/reachable_app)"
          style={{
            flex: 1,
            background: '#09090e',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px',
            padding: '10px 14px',
            color: '#f4f4f6',
            fontSize: '13px',
            fontFamily: 'var(--font-mono)'
          }}
        />
        <button
          type="button"
          onClick={() => onScan(projectPath)}
          disabled={isLoading}
          style={{
            background: '#38bdf8',
            color: '#09090b',
            border: 'none',
            borderRadius: '8px',
            padding: '10px 20px',
            fontSize: '13px',
            fontWeight: 700,
            cursor: isLoading ? 'wait' : 'pointer'
          }}
        >
          {isLoading ? 'Scanning...' : '▸ Run Scan'}
        </button>
      </div>
    </div>
  );
};

export default ScanSetup;
