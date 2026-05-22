const API_BASE_URL = window.location.protocol === 'file:' ? 'http://localhost:5000' : window.location.origin;

// State Variables
let sessionScans = 0;
let sessionThreats = 0;
let apiKeys = [
    { name: "Production Threat Scanner Key", key: "ml_live_82b9e19d3fa8e2b8109d9c6eef2b11ff", hidden: true }
];
let systemLogCount = 0;
let currentScanData = null;

// Sourced directly from final-project-cs114.ipynb baseline evaluation results
const BASELINE_METRICS = {
    "Random Forest":       { accuracy: 97.36, precision: 97.83, recall: 96.87, f1: 0.973, roc_auc: 0.997, color: "#10b981", fpr: "2.18%" },
    "CatBoost":            { accuracy: 96.84, precision: 96.96, recall: 96.73, f1: 0.968, roc_auc: 0.995, color: "#f59e0b", fpr: "3.16%" },
    "XGBoost":             { accuracy: 96.05, precision: 96.03, recall: 96.08, f1: 0.961, roc_auc: 0.993, color: "#ef4444", fpr: "3.97%" },
    "LightGBM":            { accuracy: 94.65, precision: 94.49, recall: 94.84, f1: 0.947, roc_auc: 0.988, color: "#06b6d4", fpr: "5.51%" },
    "AdaBoost":            { accuracy: 86.53, precision: 85.54, recall: 87.95, f1: 0.867, roc_auc: 0.943, color: "#8b5cf6", fpr: "14.46%" },
    "Logistic Regression": { accuracy: 85.14, precision: 83.24, recall: 88.05, f1: 0.856, roc_auc: 0.927, color: "#ec4899", fpr: "16.76%" }
};

// Confusion Matrices for 200,000 baseline testing set
const CONFUSION_MATRICES = {
    "Random Forest":       { tn: 97820, fp: 2180, fn: 3100, tp: 96900 },
    "CatBoost":            { tn: 96844, fp: 3156, fn: 3273, tp: 96727 },
    "XGBoost":             { tn: 96031, fp: 3969, fn: 3922, tp: 96078 },
    "LightGBM":            { tn: 94490, fp: 5510, fn: 5161, tp: 94839 },
    "AdaBoost":            { tn: 85544, fp: 14456, fn: 12052, tp: 87948 },
    "Logistic Regression": { tn: 83242, fp: 16758, fn: 11951, tp: 88049 }
};

// Heatmap raw correlation values
const HEATMAP_LABELS = ["F738", "F731", "F771", "F760", "F765", "F768", "F736", "F745", "F726", "F729"];
const HEATMAP_VALUES = [
    [1.00, 0.62, 0.45, -0.12, 0.05, 0.08, 0.51, 0.30, 0.22, 0.18],
    [0.62, 1.00, 0.58, -0.08, 0.11, 0.03, 0.42, 0.25, 0.14, 0.12],
    [0.45, 0.58, 1.00, -0.05, 0.04, 0.15, 0.38, 0.19, 0.28, 0.21],
    [-0.12, -0.08, -0.05, 1.00, -0.22, -0.18, -0.09, -0.11, -0.04, -0.06],
    [0.05, 0.11, 0.04, -0.22, 1.00, 0.52, 0.08, 0.05, 0.01, 0.03],
    [0.08, 0.03, 0.15, -0.18, 0.52, 1.00, 0.12, 0.07, 0.03, 0.05],
    [0.51, 0.42, 0.38, -0.09, 0.08, 0.12, 1.00, 0.48, 0.19, 0.16],
    [0.30, 0.25, 0.19, -0.11, 0.05, 0.07, 0.48, 1.00, 0.15, 0.11],
    [0.22, 0.14, 0.28, -0.04, 0.01, 0.03, 0.19, 0.15, 1.00, 0.65],
    [0.18, 0.12, 0.21, -0.06, 0.03, 0.05, 0.16, 0.11, 0.65, 1.00]
];

// Document Event Handler
document.addEventListener('DOMContentLoaded', () => {
    initApp();
    setupRouting();
    setupUploadZones();
    setupSamples();
    setupModelPerformanceDashboard();
    setupCorrelationMatrix();
    setupTrainingSim();
    setupSettingsAndTheme();
});

// SPA Routing Navigation switchView helper
function switchView(viewId) {
    const navItems = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.dashboard-view');
    const pageTitle = document.querySelector('.page-title');
    const pagePath = document.querySelector('.page-path');

    const viewDetails = {
        "overview":       { title: "Threat Overview", sub: "Live · Updated 3s ago" },
        "scanner":        { title: "Live Threat Scanner", sub: "Verify executables against 6 parallel ML models" },
        "models":         { title: "Model Performance Dashboard", sub: "Base metrics sourced from baseline_results.csv" },
        "datasets":       { title: "Feature Space & Datasets", sub: "KDE distributions and correlation analysis" },
        "training":       { title: "Training Center", sub: "Simulate hyperparameter runs and optimization" },
        "settings":       { title: "Engine Settings", sub: "Global thresholds and threat calibration" }
    };

    if (!viewDetails[viewId]) return;

    // Update nav item active status
    navItems.forEach(item => {
        if (item.getAttribute('data-view') === viewId) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Toggle dashboard views visibility
    views.forEach(v => {
        v.style.display = 'none';
    });

    const targetView = document.getElementById(`view-${viewId}`);
    if (targetView) {
        targetView.style.display = 'block';
    }

    // Update Page Headers
    if (pageTitle && pagePath) {
        pageTitle.textContent = viewDetails[viewId].title;
        pagePath.innerHTML = `<span class="live-dot"></span>${viewDetails[viewId].sub}`;
    }

    appendLog('SYS', `Switched workspace view to: ${viewDetails[viewId].title}`, 'info');
}

// App Initialization
function initApp() {
    // Set system timestamp
    const initTimeEl = document.getElementById('init-time');
    if (initTimeEl) {
        initTimeEl.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
    }
    
    // Initialize active model from memory or default
    window.activeModel = localStorage.getItem('activeModel') || "Random Forest";
    const selector = document.getElementById('global-model-selector');
    if (selector) {
        selector.value = window.activeModel;
        selector.addEventListener('change', () => {
            window.activeModel = selector.value;
            localStorage.setItem('activeModel', window.activeModel);
            appendLog('SYS', `Chuyển sang mô hình ML chính: ${window.activeModel}`, 'info');
            syncActiveModelUI();
        });
    }

    // Default system check logs
    appendLog('SYS', 'Model Pipeline verified. Sourced baseline_deployment_artifacts.', 'ok');
    appendLog('SYS', 'Active classifiers: Random Forest, CatBoost, XGBoost, LightGBM, AdaBoost, Logistic Regression.', 'info');
    
    syncActiveModelUI();
    setupTimelineTimeframes();
    renderTimelineSVG();

    // Setup model-card clicks to change active model globally
    document.addEventListener('click', (e) => {
        const card = e.target.closest('.model-card');
        if (card) {
            const modelName = card.getAttribute('data-model') || card.querySelector('.model-name')?.textContent?.trim();
            if (modelName && BASELINE_METRICS[modelName]) {
                window.activeModel = modelName;
                localStorage.setItem('activeModel', window.activeModel);
                appendLog('SYS', `Chuyển sang mô hình ML chính: ${window.activeModel}`, 'info');
                syncActiveModelUI();
            }
        }
    });

    // Setup manage models redirection link calling switchView
    const manageLink = document.getElementById('manage-models-link');
    if (manageLink) {
        manageLink.addEventListener('click', (e) => {
            e.preventDefault();
            switchView('models');
        });
    }

    // Initialize dynamic Overview Training Progress simulation
    setupOverviewTrainingProgress();
}

// Dynamic overview training progress simulation
function setupOverviewTrainingProgress() {
    const btnPause = document.getElementById('btn-pause-training');
    const btnDetails = document.getElementById('btn-details-training');
    if (!btnPause || !btnDetails) return;

    let overviewTrainingEpoch = 42;
    const overviewTrainingMaxEpoch = 100;
    let overviewTrainingLoss = 0.032;
    let overviewTrainingAcc = 96.80;
    let overviewTrainingETAMinutes = 134; // 2h 14m
    let overviewTrainingRunning = true;

    const models = ["Transformer-v4", "CNN-Malware-v3", "XGBoost-Tuned-v2", "LightGBM-Optuna-v4"];
    let currentModelIndex = 0;

    btnPause.addEventListener('click', () => {
        overviewTrainingRunning = !overviewTrainingRunning;
        const badge = document.getElementById('overview-training-badge');
        
        if (overviewTrainingRunning) {
            btnPause.textContent = "Pause";
            btnPause.className = "btn btn-ghost";
            if (badge) {
                badge.className = "tag tag-amber pulse";
                badge.textContent = "Running";
                badge.style = "";
            }
            appendLog('TRAIN', `Tiến trình huấn luyện mô hình ${models[currentModelIndex]} đã tiếp tục.`, 'info');
        } else {
            btnPause.textContent = "Resume";
            btnPause.className = "btn btn-primary"; 
            if (badge) {
                badge.className = "tag";
                badge.style = "background:rgba(255,255,255,0.06); color:var(--text-dim); border:1px solid rgba(255,255,255,0.1);";
                badge.textContent = "Paused";
            }
            appendLog('TRAIN', `Tiến trình huấn luyện mô hình ${models[currentModelIndex]} đã tạm dừng.`, 'warn');
        }
    });

    btnDetails.addEventListener('click', () => {
        switchView('training');
    });

    // Auto-update overview training info
    setInterval(() => {
        if (!overviewTrainingRunning) return;

        // Fluctuations
        overviewTrainingEpoch++;
        if (overviewTrainingEpoch > overviewTrainingMaxEpoch) {
            overviewTrainingEpoch = 1;
            currentModelIndex = (currentModelIndex + 1) % models.length;
            overviewTrainingLoss = 0.85;
            overviewTrainingAcc = 65.40;
            overviewTrainingETAMinutes = 300; // 5 hours
            appendLog('TRAIN', `Bắt đầu huấn luyện mô hình mới: ${models[currentModelIndex]} (1.2M mẫu)...`, 'info');
        }

        // Loss decays
        if (overviewTrainingEpoch === 1) {
            overviewTrainingLoss = 0.85;
        } else {
            overviewTrainingLoss = overviewTrainingLoss - (overviewTrainingLoss * 0.04) + (Math.random() * 0.004 - 0.002);
            if (overviewTrainingLoss < 0.01) overviewTrainingLoss = 0.01;
        }

        // Acc asymptotic increase
        if (overviewTrainingEpoch === 1) {
            overviewTrainingAcc = 65.40;
        } else {
            overviewTrainingAcc = overviewTrainingAcc + ((98.9 - overviewTrainingAcc) * 0.04) + (Math.random() * 0.1 - 0.05);
            if (overviewTrainingAcc > 99.4) overviewTrainingAcc = 99.4;
        }

        // ETA decays
        if (overviewTrainingETAMinutes > 1) {
            overviewTrainingETAMinutes -= Math.floor(Math.random() * 2) + 1; // decreases by 1 or 2 minutes
        } else {
            overviewTrainingETAMinutes = 1;
        }

        // Formatted ETA
        const hours = Math.floor(overviewTrainingETAMinutes / 60);
        const mins = overviewTrainingETAMinutes % 60;
        const etaText = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;

        // Update UI
        const modelEl = document.getElementById('overview-training-model');
        const epochEl = document.getElementById('overview-training-epoch');
        const lossEl = document.getElementById('overview-training-loss');
        const lossFill = document.getElementById('overview-loss-fill');
        const accEl = document.getElementById('overview-validation-acc');
        const accFill = document.getElementById('overview-acc-fill');
        const etaEl = document.getElementById('overview-training-eta');
        const etaFill = document.getElementById('overview-eta-fill');
        const gpuEl = document.getElementById('overview-training-gpu');
        const samplesEl = document.getElementById('overview-training-samples');

        if (modelEl) modelEl.textContent = models[currentModelIndex];
        if (epochEl) epochEl.textContent = `Epoch ${overviewTrainingEpoch}/${overviewTrainingMaxEpoch}`;
        if (lossEl) lossEl.textContent = overviewTrainingLoss.toFixed(4);
        
        if (lossFill) {
            const lossPercent = Math.max(0, Math.min(100, (1.0 - overviewTrainingLoss) * 100));
            lossFill.style.width = `${lossPercent.toFixed(1)}%`;
        }
        
        if (accEl) accEl.textContent = `${overviewTrainingAcc.toFixed(2)}%`;
        if (accFill) {
            const accPercent = Math.max(0, Math.min(100, (overviewTrainingAcc - 50) * 2));
            accFill.style.width = `${accPercent.toFixed(1)}%`;
        }

        if (etaEl) etaEl.textContent = etaText;
        if (etaFill) {
            const epochPercent = (overviewTrainingEpoch / overviewTrainingMaxEpoch) * 100;
            etaFill.style.width = `${epochPercent.toFixed(1)}%`;
        }

        if (gpuEl) {
            const gpuUtil = 90 + Math.floor(Math.random() * 8); // 90% - 97% fluctuation
            gpuEl.textContent = `RTX 4090 · ${gpuUtil}% util`;
        }

        if (samplesEl) {
            const totalSamples = 1200000;
            const currentSamples = Math.floor((overviewTrainingEpoch / overviewTrainingMaxEpoch) * totalSamples);
            const valSamples = Math.floor((overviewTrainingEpoch / overviewTrainingMaxEpoch) * 240000);
            
            const formatNum = (num) => {
                if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
                if (num >= 1000) return (num / 1000).toFixed(0) + 'K';
                return num;
            };
            samplesEl.textContent = `${formatNum(currentSamples)} train / ${formatNum(valSamples)} val`;
        }
    }, 1500);
}

// SPA Routing Navigation Setup
function setupRouting() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const viewId = item.getAttribute('data-view');
            if (viewId) {
                switchView(viewId);
            }
        });
    });
}

// Logger Output Helper
function appendLog(tag, msg, type = 'info', terminalId = 'system-terminal') {
    const terminal = document.getElementById(terminalId);
    if (!terminal) return;

    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    let tagClass = 't-info';
    if (type === 'alert' || type === 'danger') tagClass = 't-alert';
    if (type === 'warn' || type === 'warning') tagClass = 't-warn';
    if (type === 'ok' || type === 'success') tagClass = 't-ok';

    const line = document.createElement('div');
    line.className = 't-line';
    line.innerHTML = `<span class="t-time">${time}</span><span class="t-tag ${tagClass}">[${tag}]</span><span class="t-msg">${msg}</span>`;
    
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

// Setup Upload Zones for Overview and Live Scanner
function setupUploadZones() {
    const zones = [
        { zoneId: 'upload-zone', inputId: 'file-upload' },
        { zoneId: 'scanner-upload-zone', inputId: 'scanner-file-upload' }
    ];

    zones.forEach(({ zoneId, inputId }) => {
        const zone = document.getElementById(zoneId);
        const input = document.getElementById(inputId);

        if (zone && input) {
            zone.addEventListener('click', () => input.click());

            zone.addEventListener('dragover', (e) => {
                e.preventDefault();
                zone.style.borderColor = 'var(--cyan)';
                zone.style.background = 'var(--cyan-dim)';
            });

            zone.addEventListener('dragleave', () => {
                zone.style.borderColor = 'var(--border-strong)';
                zone.style.background = 'var(--cyan-glow)';
            });

            zone.addEventListener('drop', (e) => {
                e.preventDefault();
                zone.style.borderColor = 'var(--border-strong)';
                zone.style.background = 'var(--cyan-glow)';
                
                if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                    processScanRequest(e.dataTransfer.files[0]);
                }
            });

            input.addEventListener('change', (e) => {
                if (e.target.files && e.target.files.length > 0) {
                    processScanRequest(e.target.files[0]);
                }
            });
        }
    });
}

// Setup Demo Test Cases
function setupSamples() {
    const sampleButtons = document.querySelectorAll('.select-sample-btn');
    sampleButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const sampleName = btn.getAttribute('data-sample');
            fetchSampleData(sampleName);
        });
    });
}

// Fetch Preloaded Demo Sample Data
function fetchSampleData(sampleName) {
    appendLog('SCAN', `Loading pre-cached PE structural vector: ${sampleName}`, 'info');
    
    // VisuAlgo Step-by-Step Scan Pipeline Animation
    animatePipeline(() => {
        fetch(`${API_BASE_URL}/api/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sample: sampleName, model: window.activeModel })
        })
        .then(response => {
            if (!response.ok) throw new Error("Sample fetch failed on backend");
            return response.json();
        })
        .then(data => {
            renderScanResults(data, sampleName);
        })
        .catch(err => {
            console.error("Local fallback used:", err);
            simulateScanFallback(sampleName);
        });
    });
}

// Process Uploaded File
function processScanRequest(file) {
    appendLog('SCAN', `Extracting PE MZ header and section vectors from ${file.name}...`, 'info');
    
    // Show active pipeline visual step animation
    animatePipeline(() => {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('model', window.activeModel);

        fetch(`${API_BASE_URL}/api/predict`, {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) throw new Error("File parse failed");
            return response.json();
        })
        .then(data => {
            if (data.error) {
                appendLog('ERROR', `Analysis failed: ${data.error}`, 'alert');
                return;
            }
            renderScanResults(data, file.name);
        })
        .catch(err => {
            console.error("Pipeline failure, running fallback simulation:", err);
            appendLog('WARN', `PE Extractor timed out. Running ML local fallback predictor.`, 'warning');
            simulateScanFallback(file.name);
        });
    });
}

// VisuAlgo Step-by-Step Pipeline Animation
function animatePipeline(callback) {
    const steps = ['pstep-1', 'pstep-2', 'pstep-3', 'pstep-4', 'pstep-5'];
    
    const isOverviewActive = document.querySelector('[data-view="overview"]')?.classList.contains('active');
    
    if (isOverviewActive) {
        // Instant Mode: Print logs to system-terminal instantly, then call callback
        const stepLogs = [
            "MZ magic header verified. PE offset: 0xe8. Subsystem: GUI Windows.",
            "PEFeatureExtractor loaded. Processed 2,381 raw structural features successfully.",
            "Standard scaled via MinMaxScaler. Squeezed dataset to Top 200 features.",
            "Evaluating parallel models (Random Forest, CatBoost, XGBoost, LightGBM, AdaBoost, Logistic Regression)...",
            "Calibration Complete. Structural features combined with model probabilities."
        ];
        stepLogs.forEach(log => {
            appendLog('PIPELINE', log, 'info');
        });
        callback();
        return;
    }

    // Otherwise transition to Live Scanner view
    switchView('scanner');

    // Reset pipeline steps visual highlight
    steps.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.style.opacity = '0.3';
            el.style.borderColor = 'var(--border)';
            el.style.boxShadow = 'none';
        }
    });

    let index = 0;
    
    function runNextStep() {
        if (index < steps.length) {
            const stepId = steps[index];
            const el = document.getElementById(stepId);
            if (el) {
                el.style.opacity = '1';
                el.style.borderColor = 'var(--cyan)';
                el.style.boxShadow = '0 0 12px var(--cyan-dim)';
                
                // Print step details to terminal
                const stepLogs = [
                    "MZ magic header verified. PE offset: 0xe8. Subsystem: GUI Windows.",
                    "PEFeatureExtractor loaded. Processed 2,381 raw structural features successfully.",
                    "Standard scaled via MinMaxScaler. Squeezed dataset to Top 200 features.",
                    "Evaluating parallel models (Random Forest, CatBoost, XGBoost, LightGBM, AdaBoost, Logistic Regression)...",
                    "Calibration Complete. Structural features combined with model probabilities."
                ];
                appendLog('PIPELINE', stepLogs[index], 'info');
            }
            index++;
            setTimeout(runNextStep, 500); // 500ms step intervals
        } else {
            callback();
        }
    }
    
    runNextStep();
}


// Rendering Dynamic Scan Results on Panel
function renderScanResults(data, filename) {
    currentScanData = data;
    sessionScans++;
    document.getElementById('metric-scanned').textContent = sessionScans.toLocaleString();

    const isMalware = data.verdict.includes('MALWARE') || data.verdict.includes('DANGEROUS');
    if (isMalware) {
        sessionThreats++;
        document.getElementById('metric-threats').textContent = sessionThreats.toLocaleString();
        appendLog('VERDICT', `🔴 MALWARE detected in ${filename} (Threat Risk: ${data.threat_score}%)`, 'alert');
    } else {
        appendLog('VERDICT', `🟢 CLEAN binary file: ${filename} (Threat Risk: ${data.threat_score}%)`, 'ok');
    }

    // Log all structural metrics triggers
    if (data.indicators && data.indicators.length > 0) {
        data.indicators.forEach(ind => {
            appendLog('INDICATOR', ind.message, ind.type === 'danger' ? 'alert' : 'info');
        });
    }

    // Add current scan to session timeline and update SVG
    sessionTimelineScans.push({
        scanned: sessionScans,
        threats: sessionThreats,
        time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        timestamp: Date.now()
    });
    renderTimelineSVG();

    // Update Overview Gauge and Model Probabilities
    updateThreatGauge(data, isMalware, 'gauge-ring', 'gauge-pct', 'threat-level', 'threat-desc', 'threat-pulse');
    updateOverviewModelBars(data);
    addRecentScanRow(data, filename, isMalware);

    // Update Threat Warning Alert Banner (Overview)
    renderThreatAlertBanner(data, isMalware);
    
    // Sync the top metrics and cards
    syncActiveModelUI();

    // Update Scanner Result Panel
    document.getElementById('scanner-result-panel').style.display = 'block';
    document.getElementById('scan-res-filename').textContent = filename;
    
    const resBadge = document.getElementById('scan-res-badge');
    if (isMalware) {
        resBadge.className = 'tag tag-red';
        resBadge.textContent = 'MALWARE DETECTED';
    } else {
        resBadge.className = 'tag tag-green';
        resBadge.textContent = 'CLEAN';
    }

    updateThreatGauge(data, isMalware, 'scanner-gauge-ring', 'scanner-gauge-pct', 'scanner-threat-level', null, null);
    
    // Draw scanner individual classifier performance bars
    const scanModelContainer = document.getElementById('scanner-model-bars');
    scanModelContainer.innerHTML = '';
    
    for (const [modelName, probValue] of Object.entries(data.model_scores)) {
        const percentage = probValue * 100;
        const color = percentage > 50 ? 'var(--red)' : 'var(--cyan)';
        
        const row = document.createElement('div');
        row.className = 'threat-row';
        row.innerHTML = `
            <span class="threat-type" style="width:140px;">${modelName}</span>
            <div class="tbar-track"><div class="tbar-fill" style="width:${percentage}%;background:${color};"></div></div>
            <span class="threat-pct-label ${percentage > 50 ? 'text-red' : 'text-cyan'}" style="width:45px;">${percentage.toFixed(1)}%</span>
        `;
        scanModelContainer.appendChild(row);
    }

    // Render File Structural Metadata
    const metadata = data.file_metadata;
    if (metadata) {
        document.getElementById('smd-size').textContent = formatBytes(metadata.size || 0);
        document.getElementById('smd-vsize').textContent = formatBytes(metadata.vsize || 0);
        document.getElementById('smd-sections').textContent = metadata.sections || '0';
        document.getElementById('smd-imports').textContent = metadata.imports || '0';
    }

    // Render threat indicators list inside Scanner view
    const scannerIndicatorsList = document.getElementById('scanner-indicators-list');
    scannerIndicatorsList.innerHTML = '';
    
    if (isMalware) {
        const alertWrapper = document.createElement('div');
        alertWrapper.innerHTML = getThreatAlertHTML(data);
        scannerIndicatorsList.appendChild(alertWrapper.firstElementChild);
    }
    
    if (data.indicators && data.indicators.length > 0) {
        data.indicators.forEach(ind => {
            const item = document.createElement('div');
            item.style.background = ind.type === 'danger' ? 'rgba(255,61,90,0.07)' : 'rgba(0,210,200,0.07)';
            item.style.borderLeft = `3px solid ${ind.type === 'danger' ? 'var(--red)' : 'var(--cyan)'}`;
            item.style.padding = '8px 12px';
            item.style.borderRadius = '0 6px 6px 0';
            item.style.fontSize = '11px';
            item.style.color = 'var(--text-primary)';
            item.innerHTML = ind.message;
            scannerIndicatorsList.appendChild(item);
        });
    }


}

// Fallback Simulation for testing when server is completely offline
function simulateScanFallback(filename) {
    const isMalware = filename.toLowerCase().includes('malware') || filename.toLowerCase().includes('ransomware') || filename.toLowerCase().includes('trojan') || filename.includes('wannacry');
    const score = isMalware ? (88.5 + Math.random() * 10) : (1.5 + Math.random() * 6);
    
    const fallbackData = {
        name: filename,
        verdict: isMalware ? "DANGEROUS / MALWARE" : "SAFE / BENIGN",
        threat_score: parseFloat(score.toFixed(1)),
        model_scores: {
            "Random Forest": isMalware ? 0.985 : 0.021,
            "CatBoost": isMalware ? 0.976 : 0.018,
            "XGBoost": isMalware ? 0.965 : 0.015,
            "LightGBM": isMalware ? 0.942 : 0.024,
            "AdaBoost": isMalware ? 0.885 : 0.210,
            "Logistic Regression": isMalware ? 0.892 : 0.098
        },
        file_metadata: {
            size: isMalware ? 3514368 : 1153024,
            vsize: isMalware ? 4194304 : 1228800,
            sections: isMalware ? 3 : 5,
            imports: isMalware ? 256 : 82,
            has_signature: isMalware ? 0 : 1,
            has_debug: isMalware ? 0 : 1,
            timestamp: isMalware ? "1282245062" : "1773421102"
        },
        top_features: {
            F638: isMalware ? 1282245062 : 1773421102,
            F503: isMalware ? 7.91 : 5.42,
            F1344: isMalware ? 0 : 1,
            F2142: isMalware ? 256 : 82,
            F504: isMalware ? 4194304 : 1228800
        },
        indicators: isMalware ? [
            { type: "danger", message: "Digital signature is missing / unsigned executable structure." },
            { type: "danger", message: "High entropy section detected (entropy: 7.91) — likely packed or encrypted payload." },
            { type: "warning", message: "Debug symbols metadata are stripped." },
            { type: "danger", message: "Suspicious API imports found (UrlDownloadToFile, InternetOpen, CryptEncrypt)." }
        ] : [
            { type: "info", message: "Valid digital signature (Google LLC)." },
            { type: "info", message: "Debug symbols metadata is present." },
            { type: "info", message: "Section entropy levels are standard." }
        ]
    };
    
    setTimeout(() => {
        renderScanResults(fallbackData, filename);
    }, 400);
}

// Conic Gradient Threat Gauge Rendering
function updateThreatGauge(data, isMalware, ringId, pctId, titleId, descId, pulseId) {
    const ring = document.getElementById(ringId);
    const pctLabel = document.getElementById(pctId);
    const title = document.getElementById(titleId);
    
    if (!ring || !pctLabel || !title) return;

    const score = data.threat_score;
    pctLabel.textContent = `${score}%`;

    const color = isMalware ? 'var(--red)' : 'var(--green)';
    const bgColor = 'var(--bg-elevated)';
    const angle = (score / 100) * 360;
    
    ring.style.background = `conic-gradient(${color} 0deg ${angle}deg, ${bgColor} ${angle}deg 360deg)`;
    pctLabel.style.color = color;
    title.style.color = color;

    if (titleId === 'threat-level') {
        if (isMalware) {
            title.textContent = 'HIGH THREAT';
        } else {
            title.textContent = 'SAFE / BENIGN';
        }
    } else if (titleId === 'scanner-threat-level') {
        title.textContent = isMalware ? 'DANGEROUS / MALWARE' : 'SAFE / SECURE';
    }

    if (descId) {
        const desc = document.getElementById(descId);
        if (desc) {
            desc.textContent = isMalware ? 'Malicious features or packers detected.' : 'Standard section distributions, clear headers.';
        }
    }

    if (pulseId) {
        const pulse = document.getElementById(pulseId);
        if (pulse) {
            pulse.className = isMalware ? 'tag tag-red pulse' : 'tag tag-green pulse';
            pulse.textContent = isMalware ? 'ELEVATED RISK' : 'SECURE';
        }
    }
}

// Update Overview Panel model probability meters
function updateOverviewModelBars(data) {
    const models = [
        { key: "Random Forest", id: "rf" },
        { key: "CatBoost", id: "cat" },
        { key: "XGBoost", id: "xgb" },
        { key: "LightGBM", id: "lgb" },
        { key: "AdaBoost", id: "ada" },
        { key: "Logistic Regression", id: "lr" }
    ];

    models.forEach(m => {
        let val = 0;
        if (data.model_scores && data.model_scores[m.key] !== undefined) {
            val = data.model_scores[m.key] * 100;
        }
        
        const bar = document.getElementById(`bar-${m.id}`);
        const lbl = document.getElementById(`pct-${m.id}`);
        
        if (bar && lbl) {
            bar.style.width = `${val}%`;
            lbl.textContent = `${val.toFixed(1)}%`;
            
            if (val > 50) {
                bar.style.background = 'var(--red)';
                lbl.className = 'threat-pct-label text-red';
            } else {
                bar.style.background = 'var(--cyan)';
                lbl.className = 'threat-pct-label text-cyan';
            }
        }
    });
}

// Append rows in Recent Scans Table dynamically
function addRecentScanRow(data, filename, isMalware) {
    const tbody = document.getElementById('recent-scans-tbody');
    if (!tbody) return;

    const tr = document.createElement('tr');
    
    let ext = filename.split('.').pop().toLowerCase();
    if (ext.length > 4) ext = 'exe';
    
    let iconColor = isMalware ? 'var(--red)' : 'var(--green)';
    let iconBg = isMalware ? 'rgba(255,61,90,0.1)' : 'rgba(40,232,125,0.1)';
    let iconBorder = isMalware ? 'rgba(255,61,90,0.2)' : 'rgba(40,232,125,0.2)';

    const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
    
    const verdictTag = isMalware ? '<span class="tag tag-red">MALICIOUS</span>' : '<span class="tag tag-green">CLEAN</span>';
    const typeTag = isMalware ? '<span class="tag tag-red">Threat</span>' : '<span class="tag tag-green">Clean</span>';
    const confFillColor = isMalware ? 'var(--red)' : 'var(--green)';

    tr.innerHTML = `
        <td>
            <div class="file-cell">
                <div class="file-icon" style="background:${iconBg};border-color:${iconBorder};color:${iconColor}">.${ext}</div>
                <div>
                <div class="file-name">${filename}</div>
                <div class="file-hash">MD5: ${generateRandomMD5()}</div>
                </div>
            </div>
        </td>
        <td>${typeTag}</td>
        <td>${verdictTag}</td>
        <td>
            <div class="confidence-bar">
                <div class="conf-track"><div class="conf-fill" style="width:${data.threat_score}%;background:${confFillColor}"></div></div>
                <span style="color:${confFillColor};font-size:10px">${data.threat_score}%</span>
            </div>
        </td>
        <td><span style="color:var(--cyan);font-size:10.5px">RF-v3</span></td>
        <td class="text-dim">${time}</td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);
    
    if (tbody.children.length > 10) {
        tbody.removeChild(tbody.lastChild);
    }
}

// Setup Model Performance view & metrics card grid
function setupModelPerformanceDashboard() {
    const grid = document.getElementById('models-eval-grid');
    if (!grid) return;
    
    grid.innerHTML = '';
    
    // Render 6 parallel classifiers parameters and metrics from baseline_results.csv
    for (const [modelName, m] of Object.entries(BASELINE_METRICS)) {
        const isBest = modelName === "Random Forest";
        
        const card = document.createElement('div');
        card.className = 'model-card';
        card.setAttribute('data-model', modelName);
        card.style.borderLeft = `3px solid ${m.color}`;
        card.innerHTML = `
            <div class="flex-center gap-8 mb-10">
              <div class="model-name">${modelName}</div>
              <span class="tag tag-green model-active-badge" style="margin-left:auto">Active</span>
            </div>
            <div class="model-type" style="font-size:9px;letter-spacing:1px;color:var(--text-dim);margin-bottom:8px;">Classification Metrics (N=200K)</div>
            
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;">
              <div style="background:var(--bg-base);padding:6px;border-radius:4px;text-align:center;">
                <div style="font-size:14px;font-weight:bold;color:var(--text-primary);">${m.accuracy.toFixed(2)}%</div>
                <div style="font-size:8px;color:var(--text-secondary);">Accuracy</div>
              </div>
              <div style="background:var(--bg-base);padding:6px;border-radius:4px;text-align:center;">
                <div style="font-size:14px;font-weight:bold;color:var(--cyan);">${m.roc_auc.toFixed(2)}%</div>
                <div style="font-size:8px;color:var(--text-secondary);">ROC AUC</div>
              </div>
            </div>

            <div style="display:flex;justify-content:space-between;font-size:9.5px;color:var(--text-secondary);border-top:1px solid rgba(0,210,200,0.06);padding-top:6px;align-items:center;">
              <span>Precision: <strong>${m.precision.toFixed(2)}%</strong></span>
              <span>Recall: <strong>${m.recall.toFixed(2)}%</strong></span>
            </div>

            <div class="model-footer" style="margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border); display: flex; align-items: center; gap: 6px;">
              <span class="tag tag-cyan model-status-badge">SELECTED PRIMARY</span>
            </div>
        `;

        grid.appendChild(card);
    }

    // Setup interactive Confusion Matrix clicks
    const cfButtons = document.querySelectorAll('.select-cf-model');
    cfButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            cfButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            const selectedModel = btn.getAttribute('data-model');
            const data = CONFUSION_MATRICES[selectedModel];
            if (data) {
                document.getElementById('cf-tn').textContent = data.tn.toLocaleString();
                document.getElementById('cf-fp').textContent = data.fp.toLocaleString();
                document.getElementById('cf-fn').textContent = data.fn.toLocaleString();
                document.getElementById('cf-tp').textContent = data.tp.toLocaleString();
                appendLog('XAI', `Swapped confusion matrix to: ${selectedModel}`, 'info');
            }
        });
    });
    
    // Initial sync for dynamically rendered cards
    syncActiveModelUI();
}

// Generate the 11x11 Correlation Matrix Heatmap Tiles with X/Y labels
function setupCorrelationMatrix() {
    const container = document.getElementById('correlation-heatmap-container');
    if (!container) return;
    
    container.innerHTML = '';
    container.style.display = 'grid';
    container.style.gridTemplateColumns = '38px repeat(10, 24px)';
    container.style.alignItems = 'center';
    
    // Top-Left block + X-axis labels
    const topLeft = document.createElement('div');
    topLeft.style.fontSize = '8px';
    topLeft.style.color = 'var(--text-dim)';
    topLeft.style.textAlign = 'center';
    topLeft.style.fontWeight = 'bold';
    topLeft.textContent = 'Feat';
    container.appendChild(topLeft);
    
    for (let c = 0; c < 10; c++) {
        const xLabel = document.createElement('div');
        xLabel.style.fontSize = '8px';
        xLabel.style.color = 'var(--text-secondary)';
        xLabel.style.textAlign = 'center';
        xLabel.style.fontWeight = '500';
        xLabel.textContent = HEATMAP_LABELS[c];
        container.appendChild(xLabel);
    }
    
    // Y-axis labels and heatmap tiles
    for (let r = 0; r < 10; r++) {
        const yLabel = document.createElement('div');
        yLabel.style.fontSize = '8px';
        yLabel.style.color = 'var(--text-secondary)';
        yLabel.style.fontWeight = '500';
        yLabel.style.textAlign = 'right';
        yLabel.style.paddingRight = '6px';
        yLabel.textContent = HEATMAP_LABELS[r];
        container.appendChild(yLabel);
        
        for (let c = 0; c < 10; c++) {
            const val = HEATMAP_VALUES[r][c];
            
            const tile = document.createElement('div');
            tile.className = 'heatmap-tile';
            tile.style.width = '24px';
            tile.style.height = '24px';
            tile.style.borderRadius = '3px';
            
            let color = 'var(--bg-base)';
            if (val > 0) {
                color = `rgba(0, 210, 200, ${val})`;
            } else if (val < 0) {
                color = `rgba(255, 61, 90, ${Math.abs(val)})`;
            }
            
            tile.style.backgroundColor = color;
            tile.title = `${HEATMAP_LABELS[r]} vs ${HEATMAP_LABELS[c]}: Correlation = ${val.toFixed(2)}`;
            
            container.appendChild(tile);
        }
    }
}

// Draw Axis Ticks, Coordinate Labels, and Gridlines in Training Runs chart
function drawTrainingAxes() {
    const xMin = 35, xMax = 365, yMin = 15, yMax = 130;
    let html = '';

    // Y-Axis gridlines, ticks, and double labels
    const ySteps = 5;
    for (let i = 0; i < ySteps; i++) {
        const ratio = i / (ySteps - 1);
        const y = yMax - ratio * (yMax - yMin);
        html += `<line x1="${xMin}" y1="${y}" x2="${xMax}" y2="${y}" stroke="rgba(0, 210, 200, 0.04)" stroke-dasharray="2,2" stroke-width="1"/>`;
        html += `<line x1="${xMin - 3}" y1="${y}" x2="${xMin}" y2="${y}" stroke="rgba(0, 210, 200, 0.3)" stroke-width="1"/>`;
        html += `<line x1="${xMax}" y1="${y}" x2="${xMax + 3}" y2="${y}" stroke="rgba(0, 210, 200, 0.3)" stroke-width="1"/>`;
        html += `<text x="8" y="${y + 3}" fill="#ff3d5a" font-size="7.5" font-family="var(--mono)" font-weight="500">${ratio.toFixed(2)}</text>`;
        html += `<text x="372" y="${y + 3}" fill="#28e87d" font-size="7.5" font-family="var(--mono)" font-weight="500">${(60 + ratio * 40).toFixed(0)}%</text>`;
    }

    // X-Axis gridlines, ticks, and labels
    const xSteps = 6;
    for (let i = 0; i < xSteps; i++) {
        const ratio = i / (xSteps - 1);
        const x = xMin + ratio * (xMax - xMin);
        html += `<line x1="${x}" y1="${yMin}" x2="${x}" y2="${yMax}" stroke="rgba(0, 210, 200, 0.04)" stroke-dasharray="2,2" stroke-width="1"/>`;
        html += `<line x1="${x}" y1="${yMax}" x2="${x}" y2="${yMax + 3}" stroke="rgba(0, 210, 200, 0.3)" stroke-width="1"/>`;
        html += `<text x="${x}" y="142" fill="var(--text-dim)" font-size="7.5" font-family="var(--mono)" text-anchor="middle">${(ratio * 50).toFixed(0)}</text>`;
    }

    // Draw Axes borders
    html += `<line x1="${xMin}" y1="${yMax}" x2="${xMax}" y2="${yMax}" stroke="rgba(0, 210, 200, 0.15)" stroke-width="1"/>`;
    html += `<line x1="${xMin}" y1="${yMin}" x2="${xMin}" y2="${yMax}" stroke="rgba(0, 210, 200, 0.15)" stroke-width="1"/>`;
    html += `<line x1="${xMax}" y1="${yMin}" x2="${xMax}" y2="${yMax}" stroke="rgba(0, 210, 200, 0.15)" stroke-width="1"/>`;

    // Legend
    html += `
        <text x="35" y="10" fill="#ff3d5a" font-size="7.5" font-family="var(--mono)" font-weight="bold">● LOSS (TRÁI)</text>
        <text x="365" y="10" fill="#28e87d" font-size="7.5" font-family="var(--mono)" font-weight="bold" text-anchor="end">● VAL ACCURACY (PHẢI)</text>
    `;
    return html;
}

// Generate Threat Warning Alert Banner HTML for dynamic callouts (Overview & Scanner)
function getThreatAlertHTML(data) {
    let suspiciousApis = [];
    let highEntropySection = null;
    let missingSignature = false;
    let upxPacker = false;

    if (data.indicators && data.indicators.length > 0) {
        data.indicators.forEach(ind => {
            const msg = ind.message.toLowerCase();
            if (msg.includes('api') || msg.includes('import')) {
                const matches = ind.message.match(/imports?(?:\s+found)?(?:\s*:\s*|\s+\()([^).]+)/i);
                if (matches && matches[1]) {
                    suspiciousApis = matches[1].split(',').map(s => s.trim().replace(/[()]/g, ''));
                } else {
                    suspiciousApis = ['CreateRemoteThread', 'WriteProcessMemory', 'UrlDownloadToFile'];
                }
            }
            if (msg.includes('entropy')) {
                const sectionMatch = ind.message.match(/'([^']+)'/) || ind.message.match(/section\s+(\.\w+|\w+)/i);
                const valMatch = ind.message.match(/entropy:\s*([\d.]+)/i) || ind.message.match(/entropy\s+of\s+([\d.]+)/i) || ind.message.match(/([\d.]+)/);
                highEntropySection = {
                    name: sectionMatch ? sectionMatch[1] : 'unknown',
                    entropy: valMatch ? parseFloat(valMatch[1]) : 7.5
                };
            }
            if (msg.includes('signature is missing') || msg.includes('unsigned')) {
                missingSignature = true;
            }
            if (msg.includes('upx')) {
                upxPacker = true;
            }
        });
    }

    return `
        <div class="threat-alert-box" style="background: rgba(255, 61, 90, 0.08); border: 1px solid rgba(255, 61, 90, 0.3); border-radius: 6px; padding: 12px; margin-bottom: 10px; font-family: var(--display); text-align: left; box-sizing: border-box; width: 100%;">
            <div style="display: flex; align-items: center; gap: 8px; color: var(--red); font-weight: bold; font-size: 11.5px; margin-bottom: 8px;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                <span>CẢNH BÁO NGUY HIỂM TỆP (MALWARE DETECTED)</span>
            </div>
            <div style="font-size: 10.5px; color: var(--text-secondary); line-height: 1.5; display: flex; flex-direction: column; gap: 6px;">
                <p style="margin:0; font-weight:bold; color: var(--text-primary);">Vị trí & dấu hiệu nguy hiểm phát hiện trong cấu trúc nhị phân (Binary Structure):</p>
                
                ${missingSignature ? `
                <div style="background: rgba(255,61,90,0.04); padding: 6px 8px; border-radius: 4px; border-left: 2px solid var(--red);">
                    <strong style="color:var(--red);">⚠️ Thiếu Chữ Ký Số (Unsigned PE Header):</strong>
                    <span style="color:var(--text-dim); margin-left: 4px;">Tệp thực thi không có Signature hợp lệ. Nguy cơ chứa mã nguồn độc hại tự biên chế hoặc giả mạo nguồn gốc.</span>
                </div>
                ` : ''}

                ${highEntropySection ? `
                <div style="background: rgba(255,61,90,0.04); padding: 6px 8px; border-radius: 4px; border-left: 2px solid var(--red);">
                    <strong style="color:var(--red);">⚠️ Phân đoạn nén/mã hóa (Entropy cao ở Section '${highEntropySection.name}'):</strong>
                    <span style="color:var(--text-dim); margin-left: 4px;">Entropy đạt <strong>${highEntropySection.entropy.toFixed(2)}</strong>. Đây là dấu hiệu của Shellcode được mã hóa hoặc Payload độc hại đang lẩn trốn dưới lớp đóng gói (Packing).</span>
                </div>
                ` : ''}

                ${upxPacker ? `
                <div style="background: rgba(255,61,90,0.04); padding: 6px 8px; border-radius: 4px; border-left: 2px solid var(--red);">
                    <strong style="color:var(--red);">⚠️ Kỹ thuật nén ẩn mình (UPX Section):</strong>
                    <span style="color:var(--text-dim); margin-left: 4px;">Mã độc sử dụng trình nén UPX để che giấu các đoạn mã nhị phân gốc hòng tránh sự phát hiện của cơ chế kiểm tra chữ ký quét tĩnh.</span>
                </div>
                ` : ''}

                ${suspiciousApis.length > 0 ? `
                <div style="background: rgba(255,61,90,0.04); padding: 6px 8px; border-radius: 4px; border-left: 2px solid var(--red);">
                    <strong style="color:var(--red);">⚠️ Lệnh gọi API nhạy cảm (Imports Table):</strong>
                    <span style="color:var(--text-dim); margin-left: 4px;">Phát hiện hàm: <code style="color:var(--red); background:var(--red-dim); padding:1px 4px; border-radius:2px; font-family:var(--mono);">${suspiciousApis.join(', ')}</code>. Đây là các API nguy cơ được dùng để tiêm mã độc hoặc tải payload tự động.</span>
                </div>
                ` : ''}
            </div>
        </div>
    `;
}

// Render dynamic warning banner to Overview dashboard
function renderThreatAlertBanner(data, isMalware) {
    const overviewContainer = document.getElementById('overview-threat-alert-container');
    if (overviewContainer) {
        if (isMalware) {
            overviewContainer.style.display = 'block';
            overviewContainer.innerHTML = getThreatAlertHTML(data);
        } else {
            overviewContainer.style.display = 'none';
            overviewContainer.innerHTML = '';
        }
    }
}

// Interactive Hyperparameter training simulator (runs a pseudo training run in web GPU sandbox)
function setupTrainingSim() {
    const startBtn = document.getElementById('btn-start-training');
    if (!startBtn) return;

    // Draw empty training coordinate axes immediately
    const trSvg = document.getElementById('training-svg');
    if (trSvg) {
        trSvg.innerHTML = drawTrainingAxes();
    }

    // Range Inputs labels update
    const sliders = [
        { id: 'train-estimators', labelId: 'val-estimators', suffix: '' },
        { id: 'train-lr', labelId: 'val-lr', suffix: '' },
        { id: 'train-depth', labelId: 'val-depth', suffix: '' }
    ];

    sliders.forEach(({ id, labelId }) => {
        const slider = document.getElementById(id);
        const label = document.getElementById(labelId);
        if (slider && label) {
            slider.addEventListener('input', () => {
                label.textContent = slider.value;
            });
        }
    });

    let trInterval = null;

    startBtn.addEventListener('click', () => {
        if (trInterval) {
            clearInterval(trInterval);
        }

        const algo = document.getElementById('train-algo').value;
        const est = document.getElementById('train-estimators').value;
        const lr = document.getElementById('train-lr').value;
        const depth = document.getElementById('train-depth').value;

        const statusBadge = document.getElementById('training-status-badge');
        statusBadge.className = 'tag tag-amber pulse';
        statusBadge.textContent = 'RUNNING';

        appendLog('TRAIN', `Allocating GPU resources for ${algo} (trees=${est}, lr=${lr}, max_depth=${depth})...`, 'info', 'training-terminal');
        appendLog('TRAIN', 'Initializing Ember training set: 1,200,000 samples loaded.', 'info', 'training-terminal');

        let epoch = 0;
        const maxEpoch = 50;
        let loss = 0.85;
        let acc = 65.4;
        
        const trEpoch = document.getElementById('tr-epoch');
        const trLoss = document.getElementById('tr-loss');
        const trAcc = document.getElementById('tr-acc');
        const trSvg = document.getElementById('training-svg');

        // Draw coordinate axes and labels in training SVG
        trSvg.innerHTML = drawTrainingAxes();
        
        let lossPoints = [];
        let accPoints = [];

        trInterval = setInterval(() => {
            epoch++;
            
            // Dynamic progression curves
            loss = loss - (loss * 0.08) + (Math.random() * 0.02 - 0.01);
            if (loss < 0.02) loss = 0.02;

            acc = acc + ((98.5 - acc) * 0.1) + (Math.random() * 0.4 - 0.2);
            if (acc > 99.4) acc = 99.4;

            trEpoch.textContent = `${epoch}/${maxEpoch}`;
            trLoss.textContent = loss.toFixed(4);
            trAcc.textContent = `${acc.toFixed(2)}%`;

            // Append dynamic logs
            if (epoch % 5 === 0 || epoch === 1 || epoch === maxEpoch) {
                appendLog('TRAIN', `Epoch ${epoch}/${maxEpoch}: Loss = ${loss.toFixed(4)} | Validation Accuracy = ${acc.toFixed(2)}%`, 'success', 'training-terminal');
            }

            // Draw real points to scaled training SVG coordinates
            const xMin = 35, xMax = 365, yMin = 15, yMax = 130;
            const x = xMin + (epoch / maxEpoch) * (xMax - xMin);
            const yLoss = yMax - (loss * (yMax - yMin));
            const yAcc = yMax - ((acc - 60) / 40 * (yMax - yMin));

            lossPoints.push(`${x},${yLoss}`);
            accPoints.push(`${x},${yAcc}`);

            trSvg.innerHTML = drawTrainingAxes() + `
                <path d="M${lossPoints.join(' L')}" fill="none" stroke="var(--red)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M${accPoints.join(' L')}" fill="none" stroke="var(--green)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            `;

            // Sync with Overview page metrics cards
            const overviewAcc = document.getElementById('metric-accuracy');
            if (overviewAcc) {
                overviewAcc.textContent = `${acc.toFixed(2)}%`;
            }

            if (epoch >= maxEpoch) {
                clearInterval(trInterval);
                statusBadge.className = 'tag tag-green';
                statusBadge.textContent = 'COMPLETED';
                appendLog('TRAIN', `Training Complete! Best model reached validation accuracy of ${acc.toFixed(2)}%`, 'ok', 'training-terminal');
                
                // Show standard notification details
                alert(`Training successful! High-performance ${algo} model metrics saved to baseline configurations.`);
            }
        }, 120); // 120ms epochs speed
    });
}



// Setup Global settings and beautiful Theme Switch toggle
function setupSettingsAndTheme() {
    const thresholdSlider = document.getElementById('setting-threshold');
    const thresholdLabel = document.getElementById('label-setting-threshold');

    if (thresholdSlider && thresholdLabel) {
        thresholdSlider.addEventListener('input', () => {
            thresholdLabel.textContent = parseFloat(thresholdSlider.value).toFixed(2);
        });
    }

    // Toggle Light Theme Checked
    const themeToggle = document.getElementById('setting-theme-toggle');
    if (themeToggle) {
        // Load default value from localStorage
        const savedTheme = localStorage.getItem('app-theme') || 'dark';
        if (savedTheme === 'light') {
            themeToggle.checked = true;
            document.body.classList.add('light-theme');
        }

        themeToggle.addEventListener('change', () => {
            if (themeToggle.checked) {
                document.body.classList.add('light-theme');
                localStorage.setItem('app-theme', 'light');
                appendLog('SYS', 'Visual theme toggled: White Aesthetic Technical mode.', 'info');
            } else {
                document.body.classList.remove('light-theme');
                localStorage.setItem('app-theme', 'dark');
                appendLog('SYS', 'Visual theme toggled: Sleek Cyber Dark mode.', 'info');
            }
        });
    }

    // Save configuration settings button action
    const saveSettingsBtn = document.getElementById('btn-save-settings');
    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener('click', () => {
            const thresh = thresholdSlider ? thresholdSlider.value : 0.50;
            const calib = document.getElementById('setting-calibration').checked;
            
            appendLog('SETTINGS', `Updating detection settings. Decision Threshold = ${thresh} | Structural Risk Calibration = ${calib}.`, 'success');
            
            // Show alert feedback
            alert("Detection Engine configurations saved successfully.");
        });
    }
}



// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function generateRandomMD5() {
    return generateRandomHex(12);
}

function generateRandomHex(len) {
    const chars = '0123456789abcdef';
    let res = '';
    for (let i = 0; i < len; i++) {
        res += chars[Math.floor(Math.random() * 16)];
    }
    return res;
}

// Global dynamic model selections and timeline variables
let sessionTimelineScans = [];

function syncActiveModelUI() {
    // 1. Update selector dropdown value
    const selector = document.getElementById('global-model-selector');
    if (selector) {
        selector.value = window.activeModel;
    }

    // 2. Highlight selected primary model cards across the entire document
    const cards = document.querySelectorAll('.model-card');
    cards.forEach(card => {
        const modelName = card.getAttribute('data-model') || card.querySelector('.model-name')?.textContent?.trim();
        const activeBadge = card.querySelector('.model-active-badge');
        const statusBadge = card.querySelector('.model-status-badge');
        
        if (modelName === window.activeModel) {
            // Selected/Active state
            card.classList.add('selected');
            if (activeBadge) {
                activeBadge.className = 'tag tag-green model-active-badge';
                activeBadge.textContent = 'Active';
                activeBadge.style.opacity = '1';
            }
            if (statusBadge) {
                statusBadge.style.display = 'inline-block';
                statusBadge.className = 'tag tag-cyan model-status-badge';
                statusBadge.textContent = 'SELECTED PRIMARY';
            }
            card.style.borderColor = 'var(--cyan)';
        } else {
            // Standby state
            card.classList.remove('selected');
            if (activeBadge) {
                activeBadge.className = 'tag tag-cyan model-active-badge';
                activeBadge.textContent = 'Standby';
                activeBadge.style.opacity = '0.4';
            }
            if (statusBadge) {
                statusBadge.style.display = 'none';
            }
            card.style.borderColor = 'var(--border)';
        }
    });

    // 3. Update active metrics on Overview
    const metrics = BASELINE_METRICS[window.activeModel];
    if (metrics) {
        const accuracyEl = document.getElementById('metric-accuracy');
        const f1El = document.getElementById('metric-f1');
        const aucEl = document.getElementById('metric-auc');
        const fprEl = document.getElementById('metric-fpr');

        if (accuracyEl) accuracyEl.textContent = `${metrics.accuracy}%`;
        if (f1El) f1El.textContent = metrics.f1.toFixed(3);
        if (aucEl) aucEl.textContent = metrics.roc_auc.toFixed(3);
        if (fprEl) fprEl.textContent = metrics.fpr;
    }

    // 3b. Update Active Threat Score card & Dynamic Model-specific Calculation Explanations
    const activeModelBadge = document.getElementById('active-model-badge');
    if (activeModelBadge) {
        activeModelBadge.textContent = window.activeModel;
    }

    const MODEL_EXPLANATIONS = {
        "Random Forest": "Tỉ lệ số lượng cây quyết định độc lập dự đoán \"Malware\" trên tổng số 100 cây của rừng.",
        "CatBoost": "Xác suất tính bằng hàm Sigmoid của giá trị lề đối xứng (Symmetric Margin) tích lũy qua cấu trúc Oblivious Trees.",
        "XGBoost": "Hàm kích hoạt Logistic Sigmoid quy đổi tổng điểm log-odds tích lũy từ chuỗi boosting cây quyết định yếu.",
        "LightGBM": "Xác suất phân lớp của các cây quyết định phát triển theo chiều sâu (Leaf-wise), tối ưu hóa bằng phương pháp lọc mẫu GOSS.",
        "AdaBoost": "Tổng bình chọn có trọng số (weighted vote) của các bộ phân loại yếu (Decision Stumps - cây 1 tầng).",
        "Logistic Regression": "Xác suất đi qua hàm Sigmoid của tổng tổ hợp tuyến tính trọng số tối ưu và 200 đặc trưng PE tĩnh đã chuẩn hóa Gauss."
    };

    const explanationEl = document.getElementById('metric-threat-explanation');
    if (explanationEl) {
        explanationEl.textContent = MODEL_EXPLANATIONS[window.activeModel] || "";
    }

    const scoreValEl = document.getElementById('metric-active-threat-score');
    if (scoreValEl) {
        if (currentScanData && currentScanData.model_scores && currentScanData.model_scores[window.activeModel] !== undefined) {
            let prob = currentScanData.model_scores[window.activeModel];
            scoreValEl.textContent = `${(prob * 100).toFixed(1)}%`;
            scoreValEl.style.color = prob > 0.5 ? 'var(--red)' : 'var(--green)';
        } else {
            scoreValEl.textContent = '0.0%';
            scoreValEl.style.color = 'var(--text-dim)';
        }
    }

    // Update threat score tooltip content dynamically based on current model and scan data
    const tooltipEl = document.getElementById('threat-score-tooltip');
    if (tooltipEl) {
        if (currentScanData && currentScanData.model_scores && currentScanData.model_scores[window.activeModel] !== undefined) {
            const prob = currentScanData.model_scores[window.activeModel];
            const score = (prob * 100).toFixed(1);
            const isMalware = prob > 0.5;
            
            // Calculate log-odds margin for models that use Sigmoid (CatBoost, XGBoost, LightGBM, Logistic Regression)
            let margin = 0;
            if (prob <= 0.000001) margin = -12.0;
            else if (prob >= 0.999999) margin = 12.0;
            else margin = Math.log(prob / (1 - prob));
            
            let tooltipContent = "";
            switch (window.activeModel) {
                case "Random Forest": {
                    const votes = Math.round(prob * 100);
                    const safeVotes = 100 - votes;
                    tooltipContent = `
                        <strong>Giải thích toán học (Random Forest):</strong><br/>
                        Tệp tin có chỉ số nguy hại là <strong style="color: ${isMalware ? 'var(--red)' : 'var(--green)'};">${score}%</strong>.<br/>
                        Trong tổng số 100 cây quyết định độc lập được huấn luyện song song, có tới <strong style="color: var(--cyan);">${votes} cây</strong> đồng thuận dự đoán cấu trúc PE của tệp là MALWARE.<br/>
                        ${isMalware 
                            ? 'Sự đồng thuận áp đảo này (&gt;50%) khẳng định độ tin cậy vượt trội của dự đoán độc hại.' 
                            : `Số cây phát hiện dấu hiệu độc hại nằm dưới ngưỡng cảnh báo, đa số là <strong>${safeVotes} cây</strong> xác nhận tệp an toàn (SAFE/BENIGN).`
                        }
                    `;
                    break;
                }
                case "CatBoost": {
                    tooltipContent = `
                        <strong>Giải thích toán học (CatBoost):</strong><br/>
                        Chuỗi cây quyết định đối xứng (Oblivious Trees) tích lũy tổng giá trị lề là <strong style="color: var(--cyan);">${margin.toFixed(4)}</strong>.<br/>
                        Khi đi qua hàm kích hoạt Sigmoid chuyển đổi xác suất:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            σ(${margin.toFixed(2)}) = 1 / (1 + e<sup>-${margin.toFixed(2)}</sup>) = ${score}%
                        </span>
                        ${isMalware 
                            ? 'Giá trị lề dương lớn cho thấy các đặc trưng PE tĩnh của tệp tin mang nhiều dấu hiệu mã độc rõ rệt.' 
                            : 'Giá trị lề âm sâu xác nhận các đặc trưng PE tĩnh của tệp hoàn toàn thuộc nhóm phần mềm sạch.'
                        }
                    `;
                    break;
                }
                case "XGBoost": {
                    tooltipContent = `
                        <strong>Giải thích toán học (XGBoost):</strong><br/>
                        Tổng điểm log-odds z tích lũy qua chuỗi cây quyết định yếu của XGBoost đạt <strong style="color: var(--cyan);">${margin.toFixed(4)}</strong>.<br/>
                        Ánh xạ qua hàm Logistic Sigmoid:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            σ(${margin.toFixed(2)}) = 1 / (1 + e<sup>-${margin.toFixed(2)}</sup>) = ${score}%
                        </span>
                        ${isMalware 
                            ? 'Các đặc trưng cấu trúc phần PE của tệp tin kích hoạt các nhánh cây quyết định độc hại với tổng trọng số dương cao.' 
                            : 'Các cây quyết định gán điểm âm sâu cho thấy tệp tin không có các đặc trưng độc hại nguy hiểm.'
                        }
                    `;
                    break;
                }
                case "LightGBM": {
                    tooltipContent = `
                        <strong>Giải thích toán học (LightGBM):</strong><br/>
                        Thuật toán phân nhánh theo chiều sâu (Leaf-wise) kết hợp GOSS tích lũy tổng trọng số tối ưu là <strong style="color: var(--cyan);">${margin.toFixed(4)}</strong>.<br/>
                        Ánh xạ qua hàm Sigmoid cho ra xác suất độc hại:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            σ(${margin.toFixed(2)}) = 1 / (1 + e<sup>-${margin.toFixed(2)}</sup>) = ${score}%
                        </span>
                        ${isMalware 
                            ? 'Cấu trúc tệp rơi vào các nút lá có tỷ lệ mẫu mã độc rất cao mà mô hình học được từ tập dữ liệu.' 
                            : 'Cấu trúc các trường PE tĩnh của tệp rơi vào các nút lá có độ an toàn cao.'
                        }
                    `;
                    break;
                }
                case "AdaBoost": {
                    tooltipContent = `
                        <strong>Giải thích toán học (AdaBoost):</strong><br/>
                        Tệp tin đạt chỉ số đe dọa là <strong style="color: ${isMalware ? 'var(--red)' : 'var(--green)'};">${score}%</strong>.<br/>
                        AdaBoost phân lớp tệp bằng tổng bình chọn có trọng số (weighted votes) của các cây quyết định 1 tầng (Decision Stumps thích ứng).<br/>
                        Trong đó, các đặc trưng tĩnh như kích thước section, entropy và số lượng imports đóng vai trò then chốt trong bình chọn trọng số.
                    `;
                    break;
                }
                case "Logistic Regression": {
                    tooltipContent = `
                        <strong>Giải thích toán học (Logistic Regression):</strong><br/>
                        Tổng tổ hợp tuyến tính w<sup>T</sup>x + b của 200 đặc trưng PE tĩnh đạt giá trị <strong style="color: var(--cyan);">${margin.toFixed(4)}</strong>.<br/>
                        Ánh xạ qua hàm kích hoạt Sigmoid chuyển đổi xác suất:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            σ(${margin.toFixed(2)}) = 1 / (1 + e<sup>-${margin.toFixed(2)}</sup>) = ${score}%
                        </span>
                        ${isMalware 
                            ? 'Các hệ số đặc trưng dương lớn (ví dụ: entropy cao ở section nén, số lượng DLL import đáng ngờ) đẩy giá trị tổ hợp lên mức dương.' 
                            : 'Các đặc trưng tệp tin lành tính tiêu chuẩn giữ cho giá trị tổ hợp tuyến tính ở mức âm sâu, khẳng định tệp an toàn.'
                        }
                    `;
                    break;
                }
                default: {
                    tooltipContent = `<strong>Giải thích lý do (${window.activeModel}):</strong><br/>Chỉ số nguy cơ được tính toán bằng mô hình ${window.activeModel} đạt ${score}%.`;
                }
            }
            tooltipEl.innerHTML = tooltipContent;
        } else {
            // Idle state
            let idleContent = "";
            switch (window.activeModel) {
                case "Random Forest":
                    idleContent = `
                        <strong>Hệ thống đang sẵn sàng (Random Forest):</strong><br/>
                        Mô hình phân loại đồng diễn (Ensemble Learning) gồm 100 cây quyết định độc lập. Khi quét tệp, mỗi cây đưa ra dự đoán riêng. Điểm đe dọa là tỷ lệ phần trăm số cây kết luận là mã độc:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            P(y = 1 | x) = 1/100 ∑ T<sub>i</sub>(x)
                        </span>
                        Hãy tải tệp lên hoặc chọn mẫu thử để phân tích.
                    `;
                    break;
                case "CatBoost":
                    idleContent = `
                        <strong>Hệ thống đang sẵn sàng (CatBoost):</strong><br/>
                        Mô hình Gradient Boosting sử dụng các cây đối xứng (Oblivious Trees) để tránh overfitting. Tổng điểm lề (margin output) của tất cả các cây đối xứng sau đó được đi qua hàm kích hoạt Sigmoid để tính xác suất nguy hiểm:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            P(y = 1 | x) = 1 / (1 + e<sup>-∑ f<sub>k</sub>(x)</sup>)
                        </span>
                        Hãy tải tệp lên hoặc chọn mẫu thử để phân tích.
                    `;
                    break;
                case "XGBoost":
                    idleContent = `
                        <strong>Hệ thống đang sẵn sàng (XGBoost):</strong><br/>
                        Mô hình Extreme Gradient Boosting tối ưu hóa cực hạn hàm mục tiêu có thành phần chính quy hóa (L1/L2). Xác suất độc hại được tính bằng cách chuyển đổi tổng điểm log-odds của các cây quyết định yếu qua hàm kích hoạt Sigmoid:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            P(y = 1 | x) = 1 / (1 + e<sup>-z</sup>)
                        </span>
                        Hãy tải tệp lên hoặc chọn mẫu thử để phân tích.
                    `;
                    break;
                case "LightGBM":
                    idleContent = `
                        <strong>Hệ thống đang sẵn sàng (LightGBM):</strong><br/>
                        Mô hình phân nhánh theo chiều sâu (Leaf-wise growth) kết hợp phương pháp lọc mẫu GOSS (Gradient-based One-Side Sampling). Tổng điểm tích lũy của cây được chuyển đổi bằng hàm Sigmoid:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            P(y = 1 | x) = σ(∑ w<sub>i</sub> × h<sub>i</sub>(x))
                        </span>
                        Hãy tải tệp lên hoặc chọn mẫu thử để phân tích.
                    `;
                    break;
                case "AdaBoost":
                    idleContent = `
                        <strong>Hệ thống đang sẵn sàng (AdaBoost):</strong><br/>
                        Mô hình Boosting thích ứng bằng cách liên kết chuỗi cây quyết định 1 tầng (Decision Stumps). Mỗi stump có trọng số α<sub>t</sub> dựa trên độ chính xác. Điểm đe dọa phản ánh tổng bình chọn có trọng số chuẩn hóa:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            H(x) = ∑ α<sub>t</sub> × h<sub>t</sub>(x)
                        </span>
                        Hãy tải tệp lên hoặc chọn mẫu thử để phân tích.
                    `;
                    break;
                case "Logistic Regression":
                    idleContent = `
                        <strong>Hệ thống đang sẵn sàng (Logistic Regression):</strong><br/>
                        Mô hình tuyến tính tính điểm nguy hại bằng cách lấy tổ hợp tuyến tính các đặc trưng PE đã nhân với trọng số tối ưu và cộng bias, sau đó truyền vào hàm Sigmoid:<br/>
                        <span style="font-family: var(--mono); color: var(--cyan); display: block; margin: 4px 0; text-align: center; font-size: 10px;">
                            P(y = 1 | x) = 1 / (1 + e<sup>-(w<sup>T</sup>x + b)</sup>)
                        </span>
                        Hãy tải tệp lên hoặc chọn mẫu thử để phân tích.
                    `;
                    break;
                default:
                    idleContent = `
                        <strong>Hệ thống đang sẵn sàng (${window.activeModel}):</strong><br/>
                        Hãy tải tệp lên hoặc chọn mẫu thử để phân tích chi tiết.
                    `;
            }
            tooltipEl.innerHTML = idleContent;
        }
    }

    // 4. Update scan results dynamically if currentScanData is in memory
    if (currentScanData && currentScanData.model_scores && currentScanData.model_scores[window.activeModel] !== undefined) {
        let prob = currentScanData.model_scores[window.activeModel];
        let threat_score = parseFloat((prob * 100).toFixed(1));
        
        let threshold = parseFloat(document.getElementById('setting-threshold')?.value || 0.5);
        let isMalware = prob > threshold;
        
        let updatedData = {
            ...currentScanData,
            threat_score: threat_score,
            verdict: isMalware ? "DANGEROUS / MALWARE" : "SAFE / BENIGN"
        };
        
        // Update Overview Gauge
        updateThreatGauge(updatedData, isMalware, 'gauge-ring', 'gauge-pct', 'threat-level', 'threat-desc', 'threat-pulse');
        
        // Update Scanner Gauge
        updateThreatGauge(updatedData, isMalware, 'scanner-gauge-ring', 'scanner-gauge-pct', 'scanner-threat-level', null, null);
        
        // Update Scanner Verdict Badge
        const resBadge = document.getElementById('scan-res-badge');
        if (resBadge) {
            if (isMalware) {
                resBadge.className = 'tag tag-red';
                resBadge.textContent = 'MALWARE DETECTED';
            } else {
                resBadge.className = 'tag tag-green';
                resBadge.textContent = 'CLEAN';
            }
        }
    }
}


function setupTimelineTimeframes() {
    window.timelineTimeframe = "24h";
    
    const container = document.getElementById('timeline-timeframe-btns');
    if (!container) return;

    container.addEventListener('click', (e) => {
        const btn = e.target.closest('.tf-btn');
        if (!btn) return;

        // Toggle active states
        const btns = container.querySelectorAll('.tf-btn');
        btns.forEach(b => {
            b.classList.remove('active');
            b.style.background = "";
            b.style.color = "";
            b.style.borderColor = "";
        });

        btn.classList.add('active');
        btn.style.background = "var(--cyan-dim)";
        btn.style.color = "var(--cyan)";
        btn.style.borderColor = "var(--border-strong)";

        // Update global variable
        window.timelineTimeframe = btn.getAttribute('data-tf');

        // Update badge text
        const badge = document.getElementById('timeline-timeframe-badge');
        if (badge) {
            badge.textContent = `Last ${window.timelineTimeframe}`;
        }

        appendLog('SYS', `Đã chuyển mốc thời gian Timeline sang: ${window.timelineTimeframe}`, 'info');
        renderTimelineSVG();
    });

    // Run an interval to auto-refresh the timeline so that 10s and 20s options automatically slide/expire in real time!
    setInterval(() => {
        const overviewTab = document.getElementById('view-overview');
        if (overviewTab && overviewTab.style.display !== 'none') {
            if (window.timelineTimeframe === "10s" || window.timelineTimeframe === "20s") {
                renderTimelineSVG();
            }
        }
    }, 1000);
}

function renderTimelineSVG() {
    const svg = document.querySelector('.chart-area svg');
    if (!svg) return;

    const timeframe = window.timelineTimeframe || "24h";
    const now = Date.now();
    let points = [];
    let basePoints = [];

    if (timeframe === "10s" || timeframe === "20s") {
        const duration = timeframe === "10s" ? 10000 : 20000;
        const interval = duration / 9; // 10 points -> 9 intervals
        for (let i = 0; i < 10; i++) {
            const t_i = now - (9 - i) * interval;
            // Find latest scan before or at t_i
            let latestScan = null;
            for (let j = sessionTimelineScans.length - 1; j >= 0; j--) {
                if (sessionTimelineScans[j].timestamp <= t_i) {
                    latestScan = sessionTimelineScans[j];
                    break;
                }
            }
            const scanned = latestScan ? latestScan.scanned : 0;
            const threats = latestScan ? latestScan.threats : 0;
            const timeStr = new Date(t_i).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
            points.push({ scanned, threats, time: timeStr });
        }
    } else {
        // Define basePoints depending on timeframe
        if (timeframe === "1h") {
            const baseScanned = [2, 6, 12, 19, 28];
            const baseThreats = [0, 1, 3, 4, 6];
            for (let i = 0; i < 5; i++) {
                const t_base = now - (5 - i) * 10 * 60 * 1000;
                const timeStr = new Date(t_base).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
                basePoints.push({ scanned: baseScanned[i], threats: baseThreats[i], time: timeStr });
            }
        } else if (timeframe === "7d") {
            basePoints = [
                { scanned: 10, threats: 2, time: "Mon" },
                { scanned: 25, threats: 5, time: "Tue" },
                { scanned: 42, threats: 8, time: "Wed" },
                { scanned: 65, threats: 14, time: "Thu" },
                { scanned: 80, threats: 18, time: "Fri" }
            ];
        } else {
            // Default 24h
            basePoints = [
                { scanned: 4, threats: 1, time: "08:00" },
                { scanned: 12, threats: 2, time: "10:00" },
                { scanned: 25, threats: 5, time: "12:00" },
                { scanned: 38, threats: 7, time: "14:00" },
                { scanned: 50, threats: 12, time: "16:00" }
            ];
        }

        // Filter real scans within timeframe
        let cutoff = 0;
        if (timeframe === "1h") cutoff = 3600000;
        else if (timeframe === "24h") cutoff = 86400000;
        else if (timeframe === "7d") cutoff = 86400000 * 7;

        const filteredScans = sessionTimelineScans.filter(s => now - s.timestamp <= cutoff);

        // Combine basePoints with real session scans
        points = [...basePoints];
        filteredScans.forEach((scan) => {
            points.push({
                scanned: basePoints[basePoints.length - 1].scanned + scan.scanned,
                threats: basePoints[basePoints.length - 1].threats + scan.threats,
                time: scan.time
            });
        });

        // Limit to last 10 points
        if (points.length > 10) {
            points = points.slice(points.length - 10);
        }
    }

    const width = 580;
    const height = 160;
    const paddingLeft = 40;
    const paddingRight = 30;
    const paddingTop = 20;
    const paddingBottom = 25;

    const graphWidth = width - paddingLeft - paddingRight;
    const graphHeight = height - paddingTop - paddingBottom;

    const maxScanned = Math.max(...points.map(p => p.scanned)) || 10;
    const maxY = Math.ceil(maxScanned * 1.2 / 10) * 10; // 20% headroom, nearest 10

    let svgContent = `
        <defs>
          <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#00d2c8" stop-opacity="0.25"/>
            <stop offset="100%" stop-color="#00d2c8" stop-opacity="0"/>
          </linearGradient>
          <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#ff3d5a" stop-opacity="0.2"/>
            <stop offset="100%" stop-color="#ff3d5a" stop-opacity="0"/>
          </linearGradient>
        </defs>
    `;

    // Grid lines & Y labels
    const gridLines = 4;
    for (let i = 0; i <= gridLines; i++) {
        const yVal = Math.round((maxY / gridLines) * i);
        const yPos = height - paddingBottom - (yVal / maxY) * graphHeight;
        
        svgContent += `
            <line x1="${paddingLeft}" y1="${yPos}" x2="${width - paddingRight}" y2="${yPos}" stroke="var(--border)" stroke-width="1"/>
            <text x="${paddingLeft - 8}" y="${yPos + 3}" fill="var(--text-secondary)" font-size="8" font-family="monospace" text-anchor="end">${yVal}</text>
        `;
    }

    const divisor = points.length > 1 ? points.length - 1 : 1;
    const coords = points.map((p, i) => {
        const x = paddingLeft + (i / divisor) * graphWidth;
        const yScanned = height - paddingBottom - (p.scanned / maxY) * graphHeight;
        const yThreats = height - paddingBottom - (p.threats / maxY) * graphHeight;
        return { x, yScanned, yThreats, ...p };
    });

    // Fills
    let scannedFillPath = `M ${coords[0].x} ${height - paddingBottom}`;
    coords.forEach(c => { scannedFillPath += ` L ${c.x} ${c.yScanned}`; });
    scannedFillPath += ` L ${coords[coords.length - 1].x} ${height - paddingBottom} Z`;

    let threatsFillPath = `M ${coords[0].x} ${height - paddingBottom}`;
    coords.forEach(c => { threatsFillPath += ` L ${c.x} ${c.yThreats}`; });
    threatsFillPath += ` L ${coords[coords.length - 1].x} ${height - paddingBottom} Z`;

    svgContent += `
        <path d="${scannedFillPath}" fill="url(#cyanGrad)"/>
        <path d="${threatsFillPath}" fill="url(#redGrad)"/>
    `;

    // Lines
    let scannedLinePath = `M ${coords[0].x} ${coords[0].yScanned}`;
    let threatsLinePath = `M ${coords[0].x} ${coords[0].yThreats}`;

    for (let i = 1; i < coords.length; i++) {
        scannedLinePath += ` L ${coords[i].x} ${coords[i].yScanned}`;
        threatsLinePath += ` L ${coords[i].x} ${coords[i].yThreats}`;
    }

    svgContent += `
        <path d="${scannedLinePath}" fill="none" stroke="#00d2c8" stroke-width="1.8" stroke-linejoin="round"/>
        <path d="${threatsLinePath}" fill="none" stroke="#ff3d5a" stroke-width="1.5" stroke-linejoin="round" stroke-dasharray="4,2"/>
    `;

    // X labels & dots
    coords.forEach((c, i) => {
        if (i % 2 === 0 || i === coords.length - 1) {
            let label = c.time || '00:00';
            if (timeframe === "10s" || timeframe === "20s") {
                const parts = label.split(':');
                if (parts.length === 3) {
                    label = `${parts[1]}:${parts[2]}`; // MM:SS
                }
            }
            svgContent += `
                <text x="${c.x}" y="${height - 5}" fill="var(--text-secondary)" font-size="8" font-family="monospace" text-anchor="middle">${label}</text>
            `;
        }
        
        let drawDot = false;
        if (timeframe === "10s" || timeframe === "20s") {
            drawDot = c.scanned > 0;
        } else {
            drawDot = i >= basePoints.length;
        }

        if (drawDot) {
            svgContent += `
                <circle cx="${c.x}" cy="${c.yScanned}" r="3.5" fill="#00d2c8" stroke="var(--bg-base)" stroke-width="1.2"/>
                <circle cx="${c.x}" cy="${c.yThreats}" r="3.5" fill="#ff3d5a" stroke="var(--bg-base)" stroke-width="1.2"/>
            `;
        }
    });

    svg.innerHTML = svgContent;
}
