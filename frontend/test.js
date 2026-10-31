import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 1. Verify index.html
const indexPath = path.join(__dirname, 'index.html');
if (!fs.existsSync(indexPath)) {
  console.error('FAIL: frontend/index.html is missing');
  process.exit(1);
}

const html = fs.readFileSync(indexPath, 'utf-8');
if (!html.includes('PyReach') || !html.includes('dropzone-grid-layer') || !html.includes('corner-bracket')) {
  console.error('FAIL: frontend/index.html missing grid or dropzone enhancements');
  process.exit(1);
}

// 2. Verify ScanSetup.tsx
const scanSetupPath = path.join(__dirname, 'src', 'components', 'ScanSetup.tsx');
if (!fs.existsSync(scanSetupPath)) {
  console.error('FAIL: frontend/src/components/ScanSetup.tsx is missing');
  process.exit(1);
}

const scanSetupCode = fs.readFileSync(scanSetupPath, 'utf-8');
if (!scanSetupCode.includes('--mouse-x') || !scanSetupCode.includes('--mouse-y')) {
  console.error('FAIL: ScanSetup.tsx missing mouse-tracking coordinates');
  process.exit(1);
}

// 3. Verify App.tsx & index.css
const appPath = path.join(__dirname, 'src', 'App.tsx');
const cssPath = path.join(__dirname, 'src', 'index.css');

if (!fs.existsSync(appPath) || !fs.existsSync(cssPath)) {
  console.error('FAIL: frontend/src/App.tsx or index.css missing');
  process.exit(1);
}

const cssCode = fs.readFileSync(cssPath, 'utf-8');
if (!cssCode.includes('32px 32px') || !cssCode.includes('gridAmbientDrift')) {
  console.error('FAIL: index.css missing 32px grid or ambient drift keyframes');
  process.exit(1);
}

console.log('PASS: All frontend visual styling and motion design checks passed successfully (100%)');
process.exit(0);
