"""
BlueSploit UI: Web Interface
Browser-based interface for BlueSploit

Author: v33ru
"""

import os
import json
import threading
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# Flask imports with fallback
try:
    from flask import Flask, render_template_string, jsonify, request, Response
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = None


# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlueSploit Web UI</title>
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-tertiary: #1a1a25;
            --text-primary: #e0e0e0;
            --text-secondary: #888;
            --accent-cyan: #00d4ff;
            --accent-red: #ff4444;
            --accent-green: #00ff88;
            --accent-yellow: #ffaa00;
            --accent-purple: #aa44ff;
            --border: #2a2a35;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(90deg, var(--bg-secondary), var(--bg-tertiary));
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--accent-cyan);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--accent-cyan);
        }
        
        .logo span {
            color: var(--accent-red);
        }
        
        .status-bar {
            display: flex;
            gap: 1rem;
            font-size: 0.8rem;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-green);
        }
        
        .status-dot.warning { background: var(--accent-yellow); }
        .status-dot.error { background: var(--accent-red); }
        
        .container {
            display: grid;
            grid-template-columns: 300px 1fr 300px;
            grid-template-rows: 1fr 200px;
            gap: 1rem;
            padding: 1rem;
            height: calc(100vh - 60px);
        }
        
        .panel {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 4px;
            overflow: hidden;
        }
        
        .panel-header {
            background: var(--bg-tertiary);
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            font-weight: bold;
            color: var(--accent-cyan);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .panel-content {
            padding: 1rem;
            overflow-y: auto;
            height: calc(100% - 45px);
        }
        
        .devices-panel {
            grid-row: span 2;
        }
        
        .output-panel {
            grid-column: span 2;
        }
        
        .device-item, .module-item {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .device-item:hover, .module-item:hover {
            background: var(--bg-tertiary);
        }
        
        .device-item.selected, .module-item.selected {
            background: var(--bg-tertiary);
            border-left: 3px solid var(--accent-cyan);
        }
        
        .device-address {
            font-family: monospace;
            color: var(--accent-cyan);
        }
        
        .device-name {
            color: var(--text-primary);
            margin-top: 0.25rem;
        }
        
        .device-meta {
            display: flex;
            gap: 1rem;
            margin-top: 0.25rem;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }
        
        .rssi-good { color: var(--accent-green); }
        .rssi-medium { color: var(--accent-yellow); }
        .rssi-bad { color: var(--accent-red); }
        
        .module-category {
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            text-transform: uppercase;
        }
        
        .category-exploits { background: var(--accent-red); color: white; }
        .category-scanners { background: var(--accent-cyan); color: black; }
        .category-dos { background: var(--accent-yellow); color: black; }
        .category-auxiliary { background: var(--accent-purple); color: white; }
        
        .output-content {
            font-family: monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            line-height: 1.5;
        }
        
        .output-line {
            padding: 0.1rem 0;
        }
        
        .output-info { color: var(--text-primary); }
        .output-success { color: var(--accent-green); }
        .output-warning { color: var(--accent-yellow); }
        .output-error { color: var(--accent-red); }
        
        .controls {
            display: flex;
            gap: 0.5rem;
            margin-top: 1rem;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border);
            background: var(--bg-tertiary);
            color: var(--text-primary);
            cursor: pointer;
            border-radius: 4px;
            transition: all 0.2s;
            font-family: inherit;
        }
        
        .btn:hover {
            background: var(--accent-cyan);
            color: var(--bg-primary);
        }
        
        .btn-danger:hover {
            background: var(--accent-red);
        }
        
        .btn-success:hover {
            background: var(--accent-green);
            color: var(--bg-primary);
        }
        
        .options-form {
            display: grid;
            gap: 0.75rem;
        }
        
        .option-row {
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 0.5rem;
            align-items: center;
        }
        
        .option-label {
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
        
        .option-input {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 0.5rem;
            font-family: monospace;
            border-radius: 3px;
        }
        
        .option-input:focus {
            outline: none;
            border-color: var(--accent-cyan);
        }
        
        .search-box {
            width: 100%;
            padding: 0.5rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            border-radius: 3px;
            margin-bottom: 1rem;
        }
        
        .search-box:focus {
            outline: none;
            border-color: var(--accent-cyan);
        }
        
        .tabs {
            display: flex;
            border-bottom: 1px solid var(--border);
        }
        
        .tab {
            padding: 0.5rem 1rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            color: var(--text-secondary);
        }
        
        .tab.active {
            color: var(--accent-cyan);
            border-bottom-color: var(--accent-cyan);
        }
        
        .tab:hover {
            color: var(--text-primary);
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .scanning {
            animation: pulse 1s infinite;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">Blue<span>Sploit</span> Web UI</div>
        <div class="status-bar">
            <div class="status-item">
                <div class="status-dot" id="status-dot"></div>
                <span id="status-text">Ready</span>
            </div>
            <div class="status-item">
                <span>Devices: <span id="device-count">0</span></span>
            </div>
            <div class="status-item">
                <span>Modules: <span id="module-count">0</span></span>
            </div>
        </div>
    </div>
    
    <div class="container">
        <!-- Devices Panel -->
        <div class="panel devices-panel">
            <div class="panel-header">
                <span>📱 Devices</span>
                <button class="btn" onclick="scanDevices()">Scan</button>
            </div>
            <div class="panel-content">
                <input type="text" class="search-box" placeholder="Filter devices..." id="device-search">
                <div id="devices-list"></div>
            </div>
        </div>
        
        <!-- Main Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>⚡ Module</span>
                <span id="current-module">None selected</span>
            </div>
            <div class="panel-content">
                <div class="tabs">
                    <div class="tab active" onclick="showTab('options')">Options</div>
                    <div class="tab" onclick="showTab('info')">Info</div>
                </div>
                <div id="module-options" style="margin-top: 1rem;">
                    <p style="color: var(--text-secondary);">Select a module to configure</p>
                </div>
                <div class="controls">
                    <button class="btn btn-success" onclick="runModule()">▶ Run</button>
                    <button class="btn btn-danger" onclick="stopModule()">■ Stop</button>
                </div>
            </div>
        </div>
        
        <!-- Modules Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>📦 Modules</span>
            </div>
            <div class="panel-content">
                <div class="tabs">
                    <div class="tab active" data-category="all">All</div>
                    <div class="tab" data-category="exploits">Exploits</div>
                    <div class="tab" data-category="scanners">Scanners</div>
                    <div class="tab" data-category="dos">DoS</div>
                </div>
                <input type="text" class="search-box" placeholder="Search modules..." id="module-search" style="margin-top: 1rem;">
                <div id="modules-list"></div>
            </div>
        </div>
        
        <!-- Output Panel -->
        <div class="panel output-panel">
            <div class="panel-header">
                <span>📝 Output</span>
                <button class="btn" onclick="clearOutput()">Clear</button>
            </div>
            <div class="panel-content output-content" id="output"></div>
        </div>
    </div>
    
    <script>
        // State
        let devices = [];
        let modules = [];
        let selectedDevice = null;
        let selectedModule = null;
        let moduleOptions = {};
        
        // API calls
        async function fetchDevices() {
            try {
                const res = await fetch('/api/devices');
                devices = await res.json();
                renderDevices();
                document.getElementById('device-count').textContent = devices.length;
            } catch (e) {
                log('Error fetching devices: ' + e, 'error');
            }
        }
        
        async function fetchModules() {
            try {
                const res = await fetch('/api/modules');
                modules = await res.json();
                renderModules();
                document.getElementById('module-count').textContent = modules.length;
            } catch (e) {
                log('Error fetching modules: ' + e, 'error');
            }
        }
        
        async function scanDevices() {
            setStatus('Scanning...', 'warning');
            log('Starting device scan...', 'info');
            
            try {
                const res = await fetch('/api/scan', { method: 'POST' });
                const result = await res.json();
                
                if (result.success) {
                    log('Scan complete: ' + result.devices_found + ' devices found', 'success');
                    fetchDevices();
                } else {
                    log('Scan failed: ' + result.error, 'error');
                }
            } catch (e) {
                log('Scan error: ' + e, 'error');
            }
            
            setStatus('Ready', 'success');
        }
        
        async function selectModule(name) {
            selectedModule = name;
            document.getElementById('current-module').textContent = name;
            
            try {
                const res = await fetch('/api/module/' + encodeURIComponent(name));
                const info = await res.json();
                renderModuleOptions(info);
            } catch (e) {
                log('Error loading module: ' + e, 'error');
            }
            
            // Highlight selected
            document.querySelectorAll('.module-item').forEach(el => {
                el.classList.toggle('selected', el.dataset.name === name);
            });
        }
        
        async function runModule() {
            if (!selectedModule) {
                log('No module selected', 'warning');
                return;
            }
            
            setStatus('Running ' + selectedModule + '...', 'warning');
            log('Running module: ' + selectedModule, 'info');
            
            // Collect options
            const options = {};
            document.querySelectorAll('.option-input').forEach(input => {
                options[input.dataset.option] = input.value;
            });
            
            try {
                const res = await fetch('/api/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        module: selectedModule,
                        options: options
                    })
                });
                
                const result = await res.json();
                
                if (result.success) {
                    log('Module completed successfully', 'success');
                    if (result.output) {
                        result.output.forEach(line => log(line, 'info'));
                    }
                } else {
                    log('Module failed: ' + result.error, 'error');
                }
            } catch (e) {
                log('Run error: ' + e, 'error');
            }
            
            setStatus('Ready', 'success');
        }
        
        function stopModule() {
            log('Stopping module...', 'warning');
            fetch('/api/stop', { method: 'POST' });
        }
        
        // Rendering
        function renderDevices() {
            const container = document.getElementById('devices-list');
            const filter = document.getElementById('device-search').value.toLowerCase();
            
            const filtered = devices.filter(d => 
                d.address.toLowerCase().includes(filter) ||
                (d.name && d.name.toLowerCase().includes(filter))
            );
            
            container.innerHTML = filtered.map(d => {
                const rssiClass = d.rssi >= -50 ? 'rssi-good' : d.rssi >= -70 ? 'rssi-medium' : 'rssi-bad';
                const selected = selectedDevice === d.address ? 'selected' : '';
                
                return `
                    <div class="device-item ${selected}" onclick="selectDevice('${d.address}')">
                        <div class="device-address">${d.address}</div>
                        <div class="device-name">${d.name || 'Unknown'}</div>
                        <div class="device-meta">
                            <span class="${rssiClass}">${d.rssi} dBm</span>
                            <span>${d.type || 'Unknown'}</span>
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        function renderModules() {
            const container = document.getElementById('modules-list');
            const filter = document.getElementById('module-search').value.toLowerCase();
            
            const filtered = modules.filter(m => 
                m.name.toLowerCase().includes(filter)
            );
            
            container.innerHTML = filtered.map(m => {
                const categoryClass = 'category-' + m.category;
                const selected = selectedModule === m.name ? 'selected' : '';
                
                return `
                    <div class="module-item ${selected}" data-name="${m.name}" onclick="selectModule('${m.name}')">
                        <span class="module-category ${categoryClass}">${m.category}</span>
                        <div style="margin-top: 0.5rem">${m.name}</div>
                        <div style="color: var(--text-secondary); font-size: 0.8rem">${m.description || ''}</div>
                    </div>
                `;
            }).join('');
        }
        
        function renderModuleOptions(info) {
            const container = document.getElementById('module-options');
            
            if (!info.options || Object.keys(info.options).length === 0) {
                container.innerHTML = '<p style="color: var(--text-secondary);">No options available</p>';
                return;
            }
            
            container.innerHTML = `
                <div class="options-form">
                    ${Object.entries(info.options).map(([name, opt]) => `
                        <div class="option-row">
                            <label class="option-label">${name}${opt.required ? ' *' : ''}</label>
                            <input type="text" class="option-input" data-option="${name}" 
                                   value="${opt.default || ''}" placeholder="${opt.description || ''}">
                        </div>
                    `).join('')}
                </div>
            `;
            
            // Set target from selected device
            if (selectedDevice) {
                const targetInput = container.querySelector('[data-option="target"]');
                if (targetInput) {
                    targetInput.value = selectedDevice;
                }
            }
        }
        
        function selectDevice(address) {
            selectedDevice = address;
            renderDevices();
            
            // Update target in module options
            const targetInput = document.querySelector('[data-option="target"]');
            if (targetInput) {
                targetInput.value = address;
            }
            
            log('Selected device: ' + address, 'info');
        }
        
        // UI helpers
        function log(message, level = 'info') {
            const output = document.getElementById('output');
            const line = document.createElement('div');
            line.className = 'output-line output-' + level;
            line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
        }
        
        function clearOutput() {
            document.getElementById('output').innerHTML = '';
        }
        
        function setStatus(text, type = 'success') {
            document.getElementById('status-text').textContent = text;
            const dot = document.getElementById('status-dot');
            dot.className = 'status-dot';
            if (type !== 'success') dot.classList.add(type);
        }
        
        function showTab(name) {
            // Implement tab switching
        }
        
        // Event listeners
        document.getElementById('device-search').addEventListener('input', renderDevices);
        document.getElementById('module-search').addEventListener('input', renderModules);
        
        // Init
        fetchDevices();
        fetchModules();
        log('BlueSploit Web UI loaded', 'success');
        
        // Auto-refresh
        setInterval(fetchDevices, 10000);
    </script>
</body>
</html>
"""


class WebUI:
    """
    Web-based interface for BlueSploit.
    
    Features:
    - Device list view
    - Module browser
    - Option configuration
    - Live output
    - Scan controls
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 5000):
        self.host = host
        self.port = port
        self.app = None
        self.server_thread = None
        
        # Data stores
        self.devices: List[Dict] = []
        self.modules: List[Dict] = []
        self.output: List[str] = []
        self.current_module: Optional[str] = None
        self.running = False
        
        # Callbacks
        self.on_scan: Optional[callable] = None
        self.on_run: Optional[callable] = None
        
        if FLASK_AVAILABLE:
            self._setup_app()
    
    def _setup_app(self) -> None:
        """Setup Flask application"""
        self.app = Flask(__name__)
        CORS(self.app)
        
        # Routes
        @self.app.route('/')
        def index():
            return render_template_string(HTML_TEMPLATE)
        
        @self.app.route('/api/devices')
        def get_devices():
            return jsonify(self.devices)
        
        @self.app.route('/api/modules')
        def get_modules():
            return jsonify(self.modules)
        
        @self.app.route('/api/module/<path:name>')
        def get_module(name):
            for mod in self.modules:
                if mod['name'] == name:
                    return jsonify(mod)
            return jsonify({"error": "Module not found"}), 404
        
        @self.app.route('/api/scan', methods=['POST'])
        def scan():
            if self.on_scan:
                try:
                    result = self.on_scan()
                    return jsonify({
                        "success": True,
                        "devices_found": len(self.devices)
                    })
                except Exception as e:
                    return jsonify({"success": False, "error": str(e)})
            return jsonify({"success": False, "error": "Scan not configured"})
        
        @self.app.route('/api/run', methods=['POST'])
        def run():
            data = request.json
            module = data.get('module')
            options = data.get('options', {})
            
            if self.on_run:
                try:
                    result = self.on_run(module, options)
                    return jsonify({
                        "success": True,
                        "output": result.get('output', [])
                    })
                except Exception as e:
                    return jsonify({"success": False, "error": str(e)})
            return jsonify({"success": False, "error": "Run not configured"})
        
        @self.app.route('/api/stop', methods=['POST'])
        def stop():
            self.running = False
            return jsonify({"success": True})
        
        @self.app.route('/api/output')
        def get_output():
            return jsonify(self.output)
    
    def add_device(self, address: str, name: str = None, rssi: int = -100,
                   device_type: str = "Unknown") -> None:
        """Add or update device"""
        for d in self.devices:
            if d['address'] == address:
                d['name'] = name or d['name']
                d['rssi'] = rssi
                d['type'] = device_type
                return
        
        self.devices.append({
            'address': address,
            'name': name,
            'rssi': rssi,
            'type': device_type
        })
    
    def set_modules(self, modules: List[Dict]) -> None:
        """Set available modules"""
        self.modules = modules
    
    def log(self, message: str) -> None:
        """Add log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output.append(f"[{timestamp}] {message}")
        if len(self.output) > 1000:
            self.output = self.output[-1000:]
    
    def start(self, background: bool = True) -> None:
        """Start web server"""
        if not FLASK_AVAILABLE:
            print("Flask not installed. Install with: pip install flask flask-cors")
            return
        
        if background:
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()
            print(f"Web UI started at http://{self.host}:{self.port}")
        else:
            self._run_server()
    
    def _run_server(self) -> None:
        """Run Flask server"""
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)
    
    def stop(self) -> None:
        """Stop web server"""
        # Flask doesn't have a clean shutdown method
        # The server will stop when the main thread exits
        pass


def demo():
    """Demo the web UI"""
    if not FLASK_AVAILABLE:
        print("Flask not installed!")
        print("Install with: pip install flask flask-cors")
        return
    
    web = WebUI()
    
    # Add sample data
    web.add_device("AA:BB:CC:DD:EE:FF", "iPhone 14", -45, "Phone")
    web.add_device("11:22:33:44:55:66", "Galaxy S21", -62, "Phone")
    web.add_device("DE:AD:BE:EF:CA:FE", "ESP32-Device", -78, "IoT")
    
    web.set_modules([
        {
            "name": "exploits/bluefrag",
            "category": "exploits",
            "description": "Android A2DP RCE",
            "options": {
                "target": {"required": True, "description": "Target BD_ADDR"},
                "mode": {"required": False, "default": "check", "description": "Mode"}
            }
        },
        {
            "name": "scanners/ble_scanner",
            "category": "scanners", 
            "description": "BLE device discovery",
            "options": {
                "timeout": {"required": False, "default": "10", "description": "Scan timeout"}
            }
        },
        {
            "name": "dos/bluesmack",
            "category": "dos",
            "description": "L2CAP ping flood",
            "options": {
                "target": {"required": True, "description": "Target BD_ADDR"},
                "size": {"required": False, "default": "600", "description": "Packet size"}
            }
        }
    ])
    
    def on_scan():
        web.log("Scanning for devices...")
        time.sleep(2)
        web.log("Scan complete")
        return True
    
    def on_run(module, options):
        web.log(f"Running {module} with options: {options}")
        time.sleep(1)
        return {"output": ["Module executed successfully"]}
    
    web.on_scan = on_scan
    web.on_run = on_run
    
    print("Starting BlueSploit Web UI...")
    print(f"Open http://127.0.0.1:5000 in your browser")
    web.start(background=False)


if __name__ == "__main__":
    demo()
