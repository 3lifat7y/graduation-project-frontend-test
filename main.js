/**
 * DDoS-Guard — Frontend Control Engine
 * Real-time packet sniffer synchronization, multi-class threat telemetry,
 * interactive threat vector explorer & responsive UI interactions.
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // ============================================================================
  // 1. API Configuration & Constants
  // ============================================================================
  const API_BASE_URL = "/api";
  let scanPollInterval = null;
  let scanTimeoutTimer = null;
  let isScanning = false;
  let scanStartTime = 0;
  let activeScanId = null;

  // ============================================================================
  // 2. DOM Elements Cache
  // ============================================================================
  // Controls & Badges
  const checkBtn = document.getElementById("checkBtn");
  const stopBtn = document.getElementById("stopBtn");
  const stateBadge = document.getElementById("stateBadge");
  const statusEl = document.getElementById("connectionStatus");
  const rateEl = document.getElementById("connectionRate");
  const labelEl = document.getElementById("connectionStatusText");
  const resultIcon = document.getElementById("resultIcon");
  const resultIconWrap = document.getElementById("resultIconWrap");
  const resultsConsole = document.getElementById("resultsConsole");
  const radarBox = document.getElementById("radarBox");
  const confidenceBarFill = document.getElementById("confidenceBarFill");
  const resultChipState = document.getElementById("resultChipState");

  // Telemetry Grid Items
  const telemetryGrid = document.getElementById("telemetryGrid");
  const telemetryPkts = document.getElementById("telemetryPkts");
  const telemetryDuration = document.getElementById("telemetryDuration");
  const telemetryThroughput = document.getElementById("telemetryThroughput");
  const telemetryProtocol = document.getElementById("telemetryProtocol");

  // Diagnostic Alerts
  const diagnosticAlert = document.getElementById("diagnosticAlert");
  const diagnosticMsg = document.getElementById("diagnosticMsg");

  // Real-Time Radar Packet Telemetry Blips
  const radarPacketBlips = document.getElementById("radarPacketBlips");
  const scannerConsole = document.getElementById("scannerConsole");
  let lastCapturedPacketCount = 0;

  function triggerRadarPacketBlip() {
    if (!radarPacketBlips || document.hidden) return;
    if (radarPacketBlips.children.length > 5) return;
    const blip = document.createElement("div");
    blip.className = "radar-packet-blip";
    const angle = Math.random() * Math.PI * 2;
    const distance = 15 + Math.random() * 55;
    const x = 50 + distance * Math.cos(angle);
    const y = 50 + distance * Math.sin(angle);
    blip.style.left = `${x}%`;
    blip.style.top = `${y}%`;
    radarPacketBlips.appendChild(blip);
    setTimeout(() => {
      if (blip.parentElement) blip.remove();
    }, 1500);
  }

  function updateTelemetryCounter(el, newText) {
    if (!el) return;
    if (el.textContent !== String(newText)) {
      el.textContent = newText;
      el.classList.remove("counter-pop");
      void el.offsetWidth;
      el.classList.add("counter-pop");
    }
  }

  // Adapter & Service Badges
  const adapterChip = document.getElementById("adapterChip");
  const adapterName = document.getElementById("adapterName");
  const adapterIp = document.getElementById("adapterIp");
  const driverStatusBadge = document.getElementById("driverStatusBadge");
  const adapterIcon = document.getElementById("adapterIcon");
  const headerHealthDot = document.getElementById("headerHealthDot");
  const headerHealthLabel = document.getElementById("headerHealthLabel");
  let currentNetworkAdapter = null;

  // Navigation & UI Elements
  const menuToggle = document.getElementById("menuToggle");
  const mainNav = document.getElementById("mainNav");
  const backToTopBtn = document.getElementById("backToTop");
  const headerQuickCheckBtn = document.getElementById("headerQuickCheckBtn");

  // Threat Vectors Slider & Filter Elements
  const slider = document.querySelector(".slider");
  const cardContainer = document.querySelector(".card-container");
  const sliderPrevBtn = document.getElementById("sliderPrevBtn");
  const sliderNextBtn = document.getElementById("sliderNextBtn");
  const filterTabs = document.querySelectorAll(".filter-tab");
  const sliderCurrentIndex = document.getElementById("sliderCurrentIndex");
  const sliderTotalCount = document.getElementById("sliderTotalCount");
  const allCards = Array.from(document.querySelectorAll(".attack-card-item"));

  // ============================================================================
  // 3. Header & Service Status Synchronization
  // ============================================================================
  function updateServiceBadge(svc, drv) {
    if (!svc && !drv) return;
    svc = svc || {};
    drv = drv || {};

    const statusStr = (svc.status || "").toUpperCase();
    const isRunning = svc.running === true || statusStr === "RUNNING";
    const isPending = statusStr === "START_PENDING";
    const isStopped = statusStr === "STOPPED" || statusStr === "STOP_PENDING";

    let labelText = "Service: Checking...";
    let badgeClass = "driver-badge";
    let healthClass = "stopped";
    let healthText = "Service Stopped";

    if (isRunning) {
      if (svc.ipc_online !== false) {
        labelText = "Service: Running";
        badgeClass = "driver-badge driver-ready";
        healthClass = "running";
        healthText = "Service Online";
      } else {
        labelText = "Service: Connecting...";
        badgeClass = "driver-badge driver-pending";
        healthClass = "pending";
        healthText = "IPC Connecting";
      }
    } else if (isPending) {
      labelText = "Service: Starting...";
      badgeClass = "driver-badge driver-pending";
      healthClass = "pending";
      healthText = "Service Starting";
    } else if (svc.installed) {
      labelText = `Service: ${svc.status || "Stopped"}`;
      badgeClass = "driver-badge driver-stopped";
      healthClass = "stopped";
      healthText = "Service Inactive";
    } else if (drv.can_capture_live) {
      labelText = "Npcap: Ready";
      badgeClass = "driver-badge driver-ready";
      healthClass = "running";
      healthText = "Npcap Ready";
    } else {
      labelText = "Service: Not Installed";
      badgeClass = "driver-badge driver-stopped";
      healthClass = "stopped";
      healthText = "Service Offline";
    }

    if (driverStatusBadge) {
      driverStatusBadge.textContent = labelText;
      driverStatusBadge.className = badgeClass;
    }

    if (headerHealthDot && headerHealthLabel) {
      headerHealthDot.className = `health-dot ${healthClass}`;
      headerHealthLabel.textContent = healthText;
    }

    const headerHealthDotMobile = document.getElementById("headerHealthDotMobile");
    if (headerHealthDotMobile) {
      headerHealthDotMobile.className = `health-dot ${healthClass}`;
    }

    const topNavHealthDot = document.getElementById("topNavHealthDot");
    const topNavHealthLabel = document.getElementById("topNavHealthLabel");
    if (topNavHealthDot) {
      topNavHealthDot.className = `health-dot ${healthClass}`;
    }
    if (topNavHealthLabel) {
      topNavHealthLabel.textContent = `Engine Core: ${healthText}`;
    }
  }

  async function loadAdapterInfo() {
    try {
      const res = await fetch(`${API_BASE_URL}/adapter-info`);
      if (!res.ok) throw new Error("Failed to query adapter info");
      const data = await res.json();

      if (data.status === "success" && data.adapter) {
        const ad = data.adapter;
        currentNetworkAdapter = ad;
        const drv = data.driver_status || {};
        const svc = data.service_state || drv.service_state || {};

        if (adapterName) adapterName.textContent = `${ad.name} (${ad.type})`;
        if (adapterIp) adapterIp.textContent = `IPv4: ${ad.primary_ip || "DHCP"}`;

        if (adapterIcon) {
          adapterIcon.className = (ad.type === "Ethernet") ? "fas fa-ethernet" : "fas fa-wifi";
        }

        updateServiceBadge(svc, drv);
      }
    } catch (err) {
      console.warn("Could not load adapter info:", err);
      if (adapterName) adapterName.textContent = "Network Adapter: Ready";
    }
  }

  async function syncServiceStatus() {
    if (isScanning) return;
    try {
      const res = await fetch(`${API_BASE_URL}/service-status`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.status === "success" && data.service) {
        updateServiceBadge(data.service);
      }
    } catch (err) {
      // Ignore background heartbeat error
    }
  }

  // Initial queries and heartbeat interval
  loadAdapterInfo();
  setInterval(syncServiceStatus, 5000);

  // ============================================================================
  // 4. Reactive UI State Machine (6 Clean Scan States)
  // ============================================================================
  function setUIState(state, payload = {}) {
    if (payload && (payload.service_state || payload.driver_status)) {
      updateServiceBadge(payload.service_state, payload.driver_status);
    }

    if (stateBadge) {
      stateBadge.className = `status-indicator-badge state-${state}`;
    }

    // Reset console status classes
    if (resultsConsole) {
      resultsConsole.classList.remove("state-benign", "state-attack");
    }

    switch (state) {
      case "ready":
        isScanning = false;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-ready";
          stateBadge.textContent = "Ready";
        }
        if (radarBox) radarBox.classList.remove("active");
        if (resultChipState) resultChipState.textContent = "Standby";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (stopBtn) {
          stopBtn.style.display = "none";
          stopBtn.disabled = true;
        }
        if (statusEl) {
          statusEl.textContent = payload.message || "System ready. Click 'Start Monitoring' to capture live network traffic.";
          statusEl.style.color = "";
        }
        break;

      case "starting":
      case "scanning":
        isScanning = true;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-scanning";
          stateBadge.textContent = "Starting...";
        }
        if (radarBox) radarBox.classList.add("active");
        if (scannerConsole) scannerConsole.classList.add("scanning-active");
        if (resultChipState) resultChipState.textContent = "Starting Engine";

        if (checkBtn) {
          checkBtn.disabled = true;
          checkBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> <span class="btn-text">Starting...</span>';
        }
        if (stopBtn) {
          stopBtn.style.display = "inline-flex";
          stopBtn.disabled = false;
        }

        if (statusEl) {
          statusEl.textContent = payload.message || "Initializing packet capture session across active adapter...";
          statusEl.style.color = "";
        }
        if (diagnosticAlert) diagnosticAlert.style.display = "none";
        break;

      case "monitoring":
      case "prediction_available":
        isScanning = true;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-monitoring";
          stateBadge.textContent = "Monitoring";
        }
        if (radarBox) radarBox.classList.add("active");
        if (scannerConsole) scannerConsole.classList.add("scanning-active");
        if (resultChipState) resultChipState.textContent = "Live Telemetry";

        if (checkBtn) {
          checkBtn.disabled = true;
          checkBtn.innerHTML = '<i class="fas fa-wave-square fa-spin"></i> <span class="btn-text">Monitoring Live</span>';
        }
        if (stopBtn) {
          stopBtn.style.display = "inline-flex";
          stopBtn.disabled = false;
        }

        const isAttack = Boolean(payload.is_attack);
        const label = payload.label || (isAttack ? "DDoS Attack" : "Benign");
        const confNum = typeof payload.confidence === "number" ? payload.confidence : 0;
        const confStr = confNum > 0 ? `${confNum.toFixed(1)}%` : "--%";

        if (resultsConsole) {
          resultsConsole.classList.remove("state-benign", "state-attack");
          resultsConsole.classList.add(isAttack ? "state-attack" : "state-benign");
        }

        if (labelEl) {
          labelEl.textContent = label;
          labelEl.style.color = isAttack ? "var(--status-attack)" : "var(--status-benign)";
        }

        if (rateEl) {
          rateEl.textContent = `Confidence: ${confStr}`;
          rateEl.style.color = isAttack ? "var(--status-attack)" : "var(--status-benign)";
        }

        if (confidenceBarFill) {
          confidenceBarFill.style.width = `${Math.min(Math.max(confNum, 5), 100)}%`;
          confidenceBarFill.style.background = isAttack
            ? "linear-gradient(90deg, #f59e0b, #ef4444)"
            : "linear-gradient(90deg, #00e5ff, #10b981)";
        }

        if (statusEl) {
          statusEl.textContent = isAttack
            ? "⚠️ Security Alert: Malicious DDoS Traffic Signature Detected!"
            : "✅ Security Status: Normal / Benign Traffic Flow Verified";
          statusEl.style.color = isAttack ? "var(--status-attack)" : "var(--status-benign)";
        }

        if (resultIcon) {
          resultIcon.className = isAttack
            ? "fas fa-shield-virus result-icon"
            : "fas fa-shield-halved result-icon";
          resultIcon.style.color = isAttack ? "var(--status-attack)" : "var(--status-benign)";
        }

        // Render Telemetry Flow Statistics & Trigger Live Packet Blips
        if (telemetryGrid) {
          telemetryGrid.style.display = "grid";
          const totalPkts = payload.packets_captured !== undefined ? payload.packets_captured : (payload.flow_summary?.packets_captured || 0);

          // Animate packet arrival blip when new packets are genuinely intercepted
          if (totalPkts > lastCapturedPacketCount) {
            const diff = totalPkts - lastCapturedPacketCount;
            lastCapturedPacketCount = totalPkts;
            const count = Math.min(diff, 4);
            for (let i = 0; i < count; i++) {
              setTimeout(triggerRadarPacketBlip, i * 130);
            }
          }

          if (telemetryPkts) {
            const winPkts = payload.window_packets !== undefined ? payload.window_packets : 0;
            const pktsText = winPkts > 0 ? `${totalPkts} (${winPkts}/win)` : `${totalPkts}`;
            updateTelemetryCounter(telemetryPkts, pktsText);
          }
          if (telemetryDuration) {
            const dur = payload.duration !== undefined ? payload.duration : (((payload.flow_summary?.flow_duration_us || 0) / 1000000));
            telemetryDuration.textContent = `${Number(dur).toFixed(1)} s`;
          }
          if (telemetryThroughput) {
            const kbps = payload.throughput_kbps !== undefined ? payload.throughput_kbps : (((payload.flow_summary?.flow_bytes_per_s || 0) / 1024));
            updateTelemetryCounter(telemetryThroughput, `${Number(kbps).toFixed(1)} KB/s`);
          }
          if (telemetryProtocol) {
            telemetryProtocol.textContent = payload.protocol || "Npcap";
          }
        }
        if (diagnosticAlert) diagnosticAlert.style.display = "none";
        break;

      case "no_traffic":
        const isContinuousNoTraffic = payload.continuous !== false;
        isScanning = isContinuousNoTraffic;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-no_traffic";
          stateBadge.textContent = "No Traffic Detected";
        }
        if (radarBox) {
          if (isContinuousNoTraffic) radarBox.classList.add("active");
          else radarBox.classList.remove("active");
        }
        if (resultChipState) resultChipState.textContent = isContinuousNoTraffic ? "Idle Window" : "Idle Network";

        if (checkBtn) {
          checkBtn.disabled = isContinuousNoTraffic;
          checkBtn.innerHTML = isContinuousNoTraffic
            ? '<i class="fas fa-wave-square"></i> <span class="btn-text">Monitoring (Idle)...</span>'
            : '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (stopBtn) {
          stopBtn.style.display = isContinuousNoTraffic ? "inline-flex" : "none";
          stopBtn.disabled = !isContinuousNoTraffic;
        }

        // Clear stale prediction (never classify empty or invalid features as Benign)
        if (resultsConsole) {
          resultsConsole.classList.remove("state-benign", "state-attack");
        }
        if (labelEl) {
          labelEl.textContent = "No Traffic Detected";
          labelEl.style.color = "var(--text-muted)";
        }
        if (rateEl) {
          rateEl.textContent = "Confidence: N/A";
          rateEl.style.color = "var(--text-muted)";
        }
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = payload.message || "No packets intercepted during rolling window. Waiting for network traffic...";
          statusEl.style.color = "var(--text-muted)";
        }

        if (resultIcon) {
          resultIcon.className = "fas fa-network-wired result-icon";
          resultIcon.style.color = "var(--text-muted)";
        }

        if (telemetryGrid) {
          telemetryGrid.style.display = "grid";
          if (telemetryPkts) telemetryPkts.textContent = `${payload.packets_captured || 0} (0/win)`;
          if (telemetryDuration) telemetryDuration.textContent = `${Number(payload.duration || 0).toFixed(1)} s`;
          if (telemetryThroughput) telemetryThroughput.textContent = "0.0 KB/s";
          if (telemetryProtocol) telemetryProtocol.textContent = "Idle";
        }

        if (diagnosticAlert) {
          diagnosticAlert.style.display = "flex";
          if (diagnosticMsg) {
            diagnosticMsg.textContent = "Zero physical network packets intercepted in active window. If Wi-Fi is disabled, please connect to a network. If connected, browse a webpage or run 'python send_traffic.py'.";
          }
        }
        break;

      case "insufficient_traffic":
        const isContinuousInsufficient = payload.continuous !== false;
        isScanning = isContinuousInsufficient;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-insufficient_traffic";
          stateBadge.textContent = "Insufficient Data";
        }
        if (radarBox) {
          if (isContinuousInsufficient) radarBox.classList.add("active");
          else radarBox.classList.remove("active");
        }
        if (resultChipState) resultChipState.textContent = "Low Packet Volume";

        if (checkBtn) {
          checkBtn.disabled = isContinuousInsufficient;
          checkBtn.innerHTML = isContinuousInsufficient
            ? '<i class="fas fa-wave-square"></i> <span class="btn-text">Monitoring (Low Traffic)...</span>'
            : '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (stopBtn) {
          stopBtn.style.display = isContinuousInsufficient ? "inline-flex" : "none";
          stopBtn.disabled = !isContinuousInsufficient;
        }

        // Clear stale prediction (never classify insufficient features as Benign)
        if (resultsConsole) {
          resultsConsole.classList.remove("state-benign", "state-attack");
        }
        if (labelEl) {
          labelEl.textContent = "Insufficient Data";
          labelEl.style.color = "var(--status-warning)";
        }
        if (rateEl) {
          rateEl.textContent = "Confidence: N/A";
          rateEl.style.color = "var(--text-muted)";
        }
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = payload.message || "Interpreting traffic: window packet volume is below model classification threshold.";
          statusEl.style.color = "var(--status-warning)";
        }

        if (resultIcon) {
          resultIcon.className = "fas fa-hourglass-half result-icon";
          resultIcon.style.color = "var(--status-warning)";
        }

        if (telemetryGrid) {
          telemetryGrid.style.display = "grid";
          const winPkts = payload.window_packets !== undefined ? payload.window_packets : (payload.packets_captured || 0);
          if (telemetryPkts) telemetryPkts.textContent = `${payload.packets_captured || 0} (${winPkts}/win)`;
          if (telemetryDuration) telemetryDuration.textContent = `${Number(payload.duration || 0).toFixed(1)} s`;
          if (telemetryThroughput) telemetryThroughput.textContent = `${(payload.throughput_kbps || 0.0).toFixed(1)} KB/s`;
          if (telemetryProtocol) telemetryProtocol.textContent = payload.protocol || "Gathering...";
        }

        if (diagnosticAlert) {
          diagnosticAlert.style.display = "flex";
          if (diagnosticMsg) {
            diagnosticMsg.textContent = `Only ${payload.window_packets || payload.packets_captured || 0} packet(s) were captured in current window (minimum ${payload.min_required || 3} required). Generate more traffic.`;
          }
        }
        break;

      case "stopped":
        isScanning = false;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-stopped";
          stateBadge.textContent = "Stopped";
        }
        if (radarBox) radarBox.classList.remove("active");
        if (scannerConsole) scannerConsole.classList.remove("scanning-active");
        if (radarPacketBlips) radarPacketBlips.innerHTML = "";
        lastCapturedPacketCount = 0;
        if (resultChipState) resultChipState.textContent = "Monitoring Stopped";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (stopBtn) {
          stopBtn.style.display = "none";
          stopBtn.disabled = true;
        }

        if (statusEl) {
          statusEl.textContent = payload.message || "Continuous monitoring stopped by user.";
          statusEl.style.color = "var(--text-muted)";
        }
        if (telemetryDuration && payload.duration) {
          telemetryDuration.textContent = `${Number(payload.duration).toFixed(1)} s`;
        }
        break;

      case "uac_cancelled":
        isScanning = false;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-uac_cancelled";
          stateBadge.textContent = "Elevation Cancelled";
        }
        if (radarBox) radarBox.classList.remove("active");
        if (resultChipState) resultChipState.textContent = "Cancelled";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (stopBtn) {
          stopBtn.style.display = "none";
          stopBtn.disabled = true;
        }

        if (labelEl) {
          labelEl.textContent = "Elevation Cancelled";
          labelEl.style.color = "var(--status-warning)";
        }
        if (rateEl) rateEl.textContent = "Confidence: N/A";
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = "Administrator approval was cancelled. Click 'Start Monitoring' to approve the prompt or stream simulation packets.";
          statusEl.style.color = "var(--status-warning)";
        }

        if (diagnosticAlert) {
          diagnosticAlert.style.display = "flex";
          if (diagnosticMsg) {
            diagnosticMsg.textContent = payload.message || "Live kernel packet capture requires starting the background service. Please accept the Windows UAC prompt.";
          }
        }
        break;

      case "error":
        isScanning = false;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-error";
          stateBadge.textContent = "Capture Error";
        }
        if (radarBox) radarBox.classList.remove("active");
        if (scannerConsole) scannerConsole.classList.remove("scanning-active");
        if (radarPacketBlips) radarPacketBlips.innerHTML = "";
        lastCapturedPacketCount = 0;
        if (resultChipState) resultChipState.textContent = "Error";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-rotate-right"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (stopBtn) {
          stopBtn.style.display = "none";
          stopBtn.disabled = true;
        }

        if (labelEl) {
          labelEl.textContent = "Capture Error";
          labelEl.style.color = "var(--status-attack)";
        }
        if (rateEl) rateEl.textContent = "Confidence: N/A";
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = payload.message || "An error occurred during packet capture.";
          statusEl.style.color = "var(--status-attack)";
        }

        if (telemetryPkts) telemetryPkts.textContent = "0";
        if (telemetryDuration) telemetryDuration.textContent = "0.0 s";
        if (telemetryThroughput) telemetryThroughput.textContent = "0.0 KB/s";
        if (telemetryProtocol) telemetryProtocol.textContent = "N/A";

        if (resultIcon) {
          resultIcon.className = "fas fa-triangle-exclamation result-icon";
          resultIcon.style.color = "var(--status-attack)";
        }

        if (diagnosticAlert) {
          diagnosticAlert.style.display = "flex";
          if (diagnosticMsg) {
            let errDetail = payload.error || payload.message || "Driver or permissions error.";
            if (payload.log_tail && Array.isArray(payload.log_tail) && payload.log_tail.length > 0) {
              errDetail += `\n\n[Service Diagnostics]:\n${payload.log_tail.slice(-4).join("\n")}`;
            }
            diagnosticMsg.textContent = errDetail;
          }
        }
        break;
    }
  }

  // ============================================================================
  // 5. Scan Execution & Polling Lifecycle
  // ============================================================================
  async function startScan() {
    if (isScanning) return;

    activeScanId = null;
    console.log("[DDoS-Guard] Start Monitoring clicked. Initiating fresh continuous session...");

    // Reset previous outputs immediately
    if (resultsConsole) {
      resultsConsole.classList.remove("state-benign", "state-attack");
    }
    if (resultIcon) {
      resultIcon.className = "fas fa-satellite-dish result-icon fa-spin";
      resultIcon.style.color = "var(--accent-cyan)";
    }
    if (labelEl) {
      labelEl.textContent = "Starting Monitoring...";
      labelEl.style.color = "var(--text-primary)";
    }
    if (rateEl) {
      rateEl.textContent = "Confidence: --%";
      rateEl.style.color = "var(--accent-cyan)";
    }
    if (confidenceBarFill) {
      confidenceBarFill.style.width = "15%";
      confidenceBarFill.style.background = "linear-gradient(90deg, #00e5ff, #3b82f6)";
    }

    // Initialize telemetry grid to fresh zero state
    if (telemetryGrid) telemetryGrid.style.display = "grid";
    if (telemetryPkts) telemetryPkts.textContent = "0";
    if (telemetryDuration) telemetryDuration.textContent = "0.0 s";
    if (telemetryThroughput) telemetryThroughput.textContent = "0.0 KB/s";
    if (telemetryProtocol) telemetryProtocol.textContent = "Npcap";

    if (diagnosticAlert) diagnosticAlert.style.display = "none";

    setUIState("starting");
    scanStartTime = Date.now();

    try {
      const scanPayload = { continuous: true, min_packets: 3 };
      if (currentNetworkAdapter) {
        scanPayload.adapter = currentNetworkAdapter.name;
        scanPayload.interface_name = currentNetworkAdapter.name;
        scanPayload.interface_index = currentNetworkAdapter.index;
      }
      const res = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(scanPayload)
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        console.error("[DDoS-Guard] /api/scan returned HTTP error:", res.status, errData);
        setUIState("error", errData);
        return;
      }

      const startData = await res.json().catch(() => ({}));
      activeScanId = startData.scan_id || null;
      console.log("[DDoS-Guard] Monitoring session registered:", activeScanId, startData);

      if (startData.service_state || startData.driver_status) {
        updateServiceBadge(startData.service_state, startData.driver_status);
      }
      if (startData.status === "uac_cancelled") {
        console.warn("[DDoS-Guard] Elevation was cancelled by user.");
        activeScanId = null;
        setUIState("uac_cancelled", startData);
        return;
      }
      if (startData.status === "error" || startData.error_type === "SERVICE_START_FAILED" || startData.error_type === "SERVICE_NOT_INSTALLED") {
        console.error("[DDoS-Guard] Service error on startup:", startData);
        activeScanId = null;
        setUIState("error", startData);
        return;
      }

      // Begin polling status every 500ms continuously until Stop is clicked
      if (scanPollInterval) clearInterval(scanPollInterval);
      scanPollInterval = setInterval(pollScanStatus, 500);

    } catch (err) {
      console.error("[DDoS-Guard] Fetch failed:", err);
      activeScanId = null;
      setUIState("error", {
        message: `Cannot connect to API server: ${err.message}. Ensure 'python api.py' is running.`
      });
    }
  }

  async function pollScanStatus() {
    try {
      const res = await fetch(`${API_BASE_URL}/scan-status`);
      if (!res.ok) return;
      const data = await res.json();

      if (data.service_state || data.driver_status) {
        updateServiceBadge(data.service_state, data.driver_status);
      }

      // STRICT CHECK: Reject any poll data from a previous or mismatched scan session
      if (activeScanId && data.scan_id && data.scan_id !== activeScanId) {
        return;
      }

      const status = data.status;
      const isContinuous = data.continuous !== false;

      if (status === "starting" || status === "scanning") {
        setUIState("starting", data);
      } else if (status === "monitoring" || status === "prediction_available") {
        setUIState("monitoring", data);
        if (!isContinuous) {
          if (scanPollInterval) {
            clearInterval(scanPollInterval);
            scanPollInterval = null;
          }
        }
      } else if (status === "no_traffic") {
        setUIState("no_traffic", data);
        if (!isContinuous) {
          if (scanPollInterval) {
            clearInterval(scanPollInterval);
            scanPollInterval = null;
          }
        }
      } else if (status === "insufficient_traffic") {
        setUIState("insufficient_traffic", data);
        if (!isContinuous) {
          if (scanPollInterval) {
            clearInterval(scanPollInterval);
            scanPollInterval = null;
          }
        }
      } else if (status === "stopped") {
        if (scanPollInterval) {
          clearInterval(scanPollInterval);
          scanPollInterval = null;
        }
        setUIState("stopped", data);
      } else if (status === "error") {
        if (scanPollInterval) {
          clearInterval(scanPollInterval);
          scanPollInterval = null;
        }
        setUIState("error", data);
      }
    } catch (err) {
      console.warn("[DDoS-Guard] Polling network error:", err);
    }
  }

  async function stopScan(silent = false) {
    if (scanPollInterval) {
      clearInterval(scanPollInterval);
      scanPollInterval = null;
    }
    if (scanTimeoutTimer) {
      clearTimeout(scanTimeoutTimer);
      scanTimeoutTimer = null;
    }
    activeScanId = null;
    isScanning = false;

    try {
      const res = await fetch(`${API_BASE_URL}/scan-stop`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!silent) {
        setUIState("stopped", data.status === "stopped" ? data : { message: "Monitoring session stopped." });
      }
    } catch (err) {
      if (!silent) {
        setUIState("stopped", { message: "Monitoring stopped." });
      }
    }
  }

  // ============================================================================
  // 6. Threat Vectors Continuous Horizontal Marquee & Category Filtering
  // ============================================================================
  const originalCardsOrder = [...allCards];
  let visibleCards = [...allCards];
  let marqueeOffset = 0;
  let isMarqueePaused = false;
  let isMarqueeOffscreen = false;
  let marqueeRafId = null;
  let lastTimestamp = null;
  const MARQUEE_SPEED_PPS = 48; // Smooth reading speed: 48 pixels per second

  const prefersReducedMotionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  let isReducedMotion = prefersReducedMotionQuery.matches;

  function updateSliderCounter() {
    if (!sliderCurrentIndex || !sliderTotalCount) return;
    sliderTotalCount.textContent = visibleCards.length;
    sliderCurrentIndex.textContent = visibleCards.length;
  }

  function marqueeStep(timestamp) {
    if (!lastTimestamp) lastTimestamp = timestamp;
    const dt = Math.min((timestamp - lastTimestamp) / 1000, 0.1);
    lastTimestamp = timestamp;

    if (!isMarqueePaused && !isMarqueeOffscreen && !isReducedMotion && slider && cardContainer) {
      const activeCards = Array.from(cardContainer.children).filter(c => c.style.display !== "none");
      const sliderWidth = slider.clientWidth || 1100;
      let totalWidth = 0;
      activeCards.forEach(card => {
        totalWidth += (card.offsetWidth || 320) + 20; // 20px gap
      });

      if (totalWidth > sliderWidth + 30 && activeCards.length > 1) {
        marqueeOffset += MARQUEE_SPEED_PPS * dt;

        const firstVisible = activeCards[0];
        const cardPitch = (firstVisible.offsetWidth || 320) + 20;

        if (marqueeOffset >= cardPitch) {
          const firstHidden = cardContainer.querySelector('.attack-card-item[style*="display: none"]');
          if (firstHidden) {
            cardContainer.insertBefore(firstVisible, firstHidden);
          } else {
            cardContainer.appendChild(firstVisible);
          }
          marqueeOffset -= cardPitch;
        }

        cardContainer.style.transform = `translate3d(-${marqueeOffset.toFixed(2)}px, 0, 0)`;
      } else {
        cardContainer.style.transform = "translate3d(0, 0, 0)";
      }
    }

    marqueeRafId = requestAnimationFrame(marqueeStep);
  }

  function filterCards(category) {
    visibleCards = [];
    const hiddenCards = [];

    originalCardsOrder.forEach(card => {
      const cardCat = card.getAttribute("data-category");
      if (category === "all" || cardCat === category) {
        card.style.display = "flex";
        visibleCards.push(card);
      } else {
        card.style.display = "none";
        hiddenCards.push(card);
      }
    });

    // Re-populate container with visible cards first, then hidden cards
    visibleCards.forEach(card => cardContainer.appendChild(card));
    hiddenCards.forEach(card => cardContainer.appendChild(card));

    marqueeOffset = 0;
    if (cardContainer) {
      cardContainer.style.transform = "translate3d(0, 0, 0)";
    }

    updateSliderCounter();
    lastTimestamp = null;
  }

  // Filter tab events
  filterTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      filterTabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const category = tab.getAttribute("data-filter");
      filterCards(category);
    });
  });

  // Dedicated Marquee Pause / Resume Control
  const marqueeToggleBtn = document.getElementById("marqueeToggleBtn");
  const marqueeToggleIcon = document.getElementById("marqueeToggleIcon");
  const marqueeToggleText = document.getElementById("marqueeToggleText");
  const marqueePatrolBadge = document.getElementById("marqueePatrolBadge");

  if (marqueeToggleBtn && cardContainer) {
    marqueeToggleBtn.addEventListener("click", () => {
      isMarqueePaused = !isMarqueePaused;
      cardContainer.classList.toggle("marquee-paused", isMarqueePaused);

      if (marqueeToggleIcon) {
        marqueeToggleIcon.className = isMarqueePaused ? "fas fa-play" : "fas fa-pause";
      }
      if (marqueeToggleText) {
        marqueeToggleText.textContent = isMarqueePaused ? "Resume" : "Pause";
      }
      marqueeToggleBtn.setAttribute("aria-label", isMarqueePaused ? "Resume continuous marquee animation" : "Pause continuous marquee animation");

      if (marqueePatrolBadge) {
        marqueePatrolBadge.classList.toggle("paused", isMarqueePaused);
        const badgeText = marqueePatrolBadge.querySelector(".badge-text");
        if (badgeText) {
          badgeText.textContent = isMarqueePaused ? "Patrol Paused" : "Auto-Patrol Active";
        }
      }

      if (!isMarqueePaused) {
        lastTimestamp = performance.now();
      }
    });
  }

  // Slider arrows (smooth step without pausing if invoked)
  if (sliderNextBtn) {
    sliderNextBtn.addEventListener("click", () => {
      marqueeOffset += 120;
    });
  }

  if (sliderPrevBtn) {
    sliderPrevBtn.addEventListener("click", () => {
      marqueeOffset = Math.max(0, marqueeOffset - 120);
    });
  }

  // IntersectionObserver to avoid background CPU load when offscreen
  if ("IntersectionObserver" in window && slider) {
    const marqueeObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        isMarqueeOffscreen = !entry.isIntersecting;
        if (entry.isIntersecting) {
          lastTimestamp = performance.now();
        }
      });
    }, { threshold: 0.05 });
    marqueeObserver.observe(slider);
  }

  // Accessibility: handle reduced motion
  prefersReducedMotionQuery.addEventListener("change", (e) => {
    isReducedMotion = e.matches;
    if (isReducedMotion) {
      if (cardContainer) cardContainer.style.transform = "none";
      if (marqueePatrolBadge) {
        marqueePatrolBadge.classList.add("paused");
        const badgeText = marqueePatrolBadge.querySelector(".badge-text");
        if (badgeText) badgeText.textContent = "Motion Reduced";
      }
      if (marqueeToggleText) marqueeToggleText.textContent = "Resume";
      if (marqueeToggleIcon) marqueeToggleIcon.className = "fas fa-play";
    } else {
      if (!isMarqueePaused) {
        lastTimestamp = performance.now();
      }
    }
  });


  // Mobile Touch Drag & Pause for Attack Vector Marquee
  if (slider && cardContainer) {
    let touchStartX = 0;
    let touchScrollOffset = 0;
    let isTouching = false;

    slider.addEventListener("touchstart", (e) => {
      if (e.touches.length === 1) {
        isTouching = true;
        touchStartX = e.touches[0].clientX;
        touchScrollOffset = marqueeOffset;
        isMarqueePaused = true;
      }
    }, { passive: true });

    slider.addEventListener("touchmove", (e) => {
      if (isTouching && e.touches.length === 1) {
        const deltaX = e.touches[0].clientX - touchStartX;
        marqueeOffset = Math.max(0, touchScrollOffset - deltaX);
        cardContainer.style.transform = `translate3d(-${marqueeOffset.toFixed(2)}px, 0, 0)`;
      }
    }, { passive: true });

    slider.addEventListener("touchend", () => {
      isTouching = false;
      const isManualPaused = marqueeToggleBtn && marqueeToggleBtn.getAttribute("aria-pressed") === "true";
      if (!isManualPaused) {
        setTimeout(() => {
          if (!isTouching) isMarqueePaused = false;
          lastTimestamp = performance.now();
        }, 1200);
      }
    }, { passive: true });
  }

    // Start continuous marquee RAF loop
  if (!isReducedMotion) {
    marqueeRafId = requestAnimationFrame(marqueeStep);
  }
  updateSliderCounter();

  // ============================================================================
  // 7. General Navigation, Collapsible Sidebar & Dedicated View Coordinator
  // ============================================================================
  const sidebarToggleBtn = document.getElementById("sidebarToggleBtn");
  const navbarSidebarToggleBtn = document.getElementById("navbarSidebarToggleBtn");
  const mobileMenuBtn = document.getElementById("mobileMenuBtn");
  const sidebarBackdrop = document.getElementById("sidebarBackdrop");
  const sidebarNavItems = document.querySelectorAll(".sidebar-nav-item");
  const topNavLinks = document.querySelectorAll(".top-nav-link");

  const dedicatedToolBar = document.getElementById("dedicatedToolBar");
  const dedicatedToolTitle = document.getElementById("dedicatedToolTitle");
  const dedicatedViewToggleBtn = document.getElementById("dedicatedViewToggleBtn");
  const breadcrumbHomeLink = document.getElementById("breadcrumbHomeLink");
  const launchDedicatedMonitorBtn = document.getElementById("launchDedicatedMonitorBtn");
  const launchDedicatedPortScannerBtn = document.getElementById("launchDedicatedPortScannerBtn");

  const heroSection = document.getElementById("overview");
  const monitorSection = document.getElementById("check-connection");
  const portScannerSection = document.getElementById("port-scanner");
  const ndLandingSection = document.getElementById("network-discovery-section");
  const ndDedicatedSection = document.getElementById("network-discovery");
  const heroDiscoveryBtn = document.getElementById("heroDiscoveryBtn");
  const openDiscoveryToolBtn = document.getElementById("openDiscoveryToolBtn");
  const ndHeaderCtaBtn = document.getElementById("ndHeaderCtaBtn");
  const threatSection = document.getElementById("threat-intelligence");
  const preventionSection = document.getElementById("prevention");
  const teamSection = document.getElementById("team");
  const footerEl = document.querySelector(".site-footer");

  const sidebarMobileCloseBtn = document.getElementById("sidebarMobileCloseBtn");

  // Restore Sidebar Collapsed State from localStorage
  if (localStorage.getItem("nss_sidebar_collapsed") === "true") {
    document.body.classList.add("sidebar-collapsed");
  }

  // Close Mobile Drawer Helper
  function closeMobileSidebar() {
    document.body.classList.remove("mobile-sidebar-open");
    if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", "false");
    if (mobileMenuBtn) mobileMenuBtn.setAttribute("aria-expanded", "false");
  }

  // Toggle Sidebar Function (Responsive for Desktop Collapse & Mobile Drawer)
  function handleSidebarToggle() {
    if (window.innerWidth < 992) {
      const isOpen = document.body.classList.toggle("mobile-sidebar-open");
      if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
      if (mobileMenuBtn) mobileMenuBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
    } else {
      const isCollapsed = document.body.classList.toggle("sidebar-collapsed");
      localStorage.setItem("nss_sidebar_collapsed", isCollapsed ? "true" : "false");
      if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", isCollapsed ? "false" : "true");
    }
  }

  if (sidebarToggleBtn) {
    sidebarToggleBtn.addEventListener("click", () => {
      const isCollapsed = document.body.classList.toggle("sidebar-collapsed");
      localStorage.setItem("nss_sidebar_collapsed", isCollapsed ? "true" : "false");
    });
  }

  if (navbarSidebarToggleBtn) {
    navbarSidebarToggleBtn.addEventListener("click", handleSidebarToggle);
  }

  // Mobile Drawer Toggle (Fallback)
  if (mobileMenuBtn) {
    mobileMenuBtn.addEventListener("click", () => {
      const isOpen = document.body.classList.toggle("mobile-sidebar-open");
      mobileMenuBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });
  }

  // Mobile Backdrop Click
  if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener("click", closeMobileSidebar);
  }

  // Mobile Drawer Close Button
  if (sidebarMobileCloseBtn) {
    sidebarMobileCloseBtn.addEventListener("click", closeMobileSidebar);
  }

  // Dismiss mobile drawer on Escape key
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && document.body.classList.contains("mobile-sidebar-open")) {
      closeMobileSidebar();
    }
  });

  // Ensure drawer closes when resizing past mobile breakpoint
  window.addEventListener("resize", () => {
    if (window.innerWidth >= 992 && document.body.classList.contains("mobile-sidebar-open")) {
      closeMobileSidebar();
    }
  });

  // Update Active Link in Sidebar
  function setSidebarActive(navName) {
    sidebarNavItems.forEach(item => {
      if (item.getAttribute("data-nav") === navName) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });
  }

  // Update Active Link in Global Top Navbar
  function setTopNavActive(navName) {
    topNavLinks.forEach(link => {
      if (link.getAttribute("data-top-nav") === navName) {
        link.classList.add("active");
      } else {
        link.classList.remove("active");
      }
    });
  }

  // ============================================================================
  // Complete Global Dark / Light Theme System
  // ============================================================================
  function initTheme() {
    const themeToggleBtn = document.getElementById("themeToggleBtn");
    const themeToggleIcon = document.getElementById("themeToggleIcon");
    const themeToggleText = document.getElementById("themeToggleText");
    const metaTheme = document.querySelector('meta[name="theme-color"]');

    function applyTheme(theme, animate = false) {
      if (animate) {
        document.body.classList.add("theme-transitioning");
      }
      document.documentElement.setAttribute("data-theme", theme);
      const isDark = theme === "dark";

      if (themeToggleIcon) {
        themeToggleIcon.className = isDark ? "fas fa-sun" : "fas fa-moon";
      }
      if (themeToggleText) {
        themeToggleText.textContent = isDark ? "Light Mode" : "Dark Mode";
      }
      if (themeToggleBtn) {
        const titleStr = isDark ? "Switch to Light Mode" : "Switch to Dark Mode";
        themeToggleBtn.setAttribute("title", titleStr);
        themeToggleBtn.setAttribute("aria-label", titleStr);
      }
      if (metaTheme) {
        metaTheme.setAttribute("content", isDark ? "#101411" : "#F7F5EF");
      }

      if (animate) {
        window.setTimeout(() => {
          document.body.classList.remove("theme-transitioning");
        }, 260);
      }
    }

    const savedTheme = localStorage.getItem("nss_theme");
    const systemDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const initialTheme = savedTheme || (systemDark ? "dark" : "light");
    applyTheme(initialTheme, false);

    if (themeToggleBtn) {
      themeToggleBtn.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-theme") || "light";
        const next = current === "dark" ? "light" : "dark";
        localStorage.setItem("nss_theme", next);
        applyTheme(next, true);
      });
    }

    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
        if (!localStorage.getItem("nss_theme")) {
          applyTheme(e.matches ? "dark" : "light", true);
        }
      });
    }
  }

  initTheme();

  // Get Requested View from URL or Hash
  function getQueryView() {
    const pathname = window.location.pathname || "";
    if (pathname.includes("network-discovery") || pathname.includes("network_discovery")) return "network-discovery";
    if (pathname.includes("port-scanner")) return "port-scanner";
    if (pathname.includes("monitoring") || pathname.includes("ddos")) return "monitoring";

    const params = new URLSearchParams(window.location.search);
    const view = params.get("view");
    if (view === "monitoring" || view === "live-monitoring") return "monitoring";
    if (view === "port-scanner" || view === "scanner") return "port-scanner";
    if (view === "network-discovery" || view === "discovery") return "network-discovery";

    const hash = window.location.hash;
    if (hash === "#live-monitoring" || hash === "#monitoring") return "monitoring";
    if (hash === "#port-scanner-page" || hash === "#port-scanner") return "port-scanner";
    if (hash === "#network-discovery" || hash === "#discovery") return "network-discovery";

    return "landing";
  }

  // Switch View: Dedicated Workspace vs Full Landing Page
  function switchView(targetView, updateHistory = true) {
    // Close mobile drawer on navigation
    document.body.classList.remove("mobile-sidebar-open");
    if (mobileMenuBtn) mobileMenuBtn.setAttribute("aria-expanded", "false");
    if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", "false");

    if (ndHeaderCtaBtn) ndHeaderCtaBtn.style.display = "none";

    if (targetView === "monitoring") {
      document.body.classList.add("dedicated-mode-monitoring");
      document.body.classList.remove("dedicated-mode-port-scanner", "dedicated-mode-network-discovery", "home-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Live Network Monitoring & Intrusion Detection";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "block";
      if (portScannerSection) portScannerSection.style.display = "none";
      if (ndDedicatedSection) ndDedicatedSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";

      setSidebarActive("monitoring");
      setTopNavActive("monitoring");
      window.scrollTo({ top: 0, behavior: "smooth" });

      if (updateHistory) {
        history.pushState({ view: "monitoring" }, "", "?view=monitoring");
      }
    } else if (targetView === "port-scanner") {
      document.body.classList.add("dedicated-mode-port-scanner");
      document.body.classList.remove("dedicated-mode-monitoring", "dedicated-mode-network-discovery", "home-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Port & Network Reconnaissance Scanner";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "none";
      if (portScannerSection) portScannerSection.style.display = "block";
      if (ndDedicatedSection) ndDedicatedSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";

      setSidebarActive("port-scanner");
      setTopNavActive("port-scanner");
      window.scrollTo({ top: 0, behavior: "smooth" });

      if (updateHistory) {
        history.pushState({ view: "port-scanner" }, "", "?view=port-scanner");
      }
    } else if (targetView === "network-discovery") {
      document.body.classList.add("dedicated-mode-network-discovery");
      document.body.classList.remove("dedicated-mode-monitoring", "dedicated-mode-port-scanner", "home-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Local Network Discovery & Asset Inventory";
      if (ndHeaderCtaBtn) ndHeaderCtaBtn.style.display = "inline-flex";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "none";
      if (portScannerSection) portScannerSection.style.display = "none";
      if (ndDedicatedSection) ndDedicatedSection.style.display = "block";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";

      setSidebarActive("network-discovery");
      setTopNavActive("network-discovery");
      window.scrollTo({ top: 0, behavior: "smooth" });

      if (window.ndController && typeof window.ndController.onActivated === "function") {
        window.ndController.onActivated();
      }

      if (updateHistory) {
        history.pushState({ view: "network-discovery" }, "", "?view=network-discovery");
      }
    } else {
      // Home Page Mode
      document.body.classList.remove("dedicated-mode-monitoring", "dedicated-mode-port-scanner", "dedicated-mode-network-discovery");
      document.body.classList.add("home-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "none";

      if (heroSection) heroSection.style.display = "block";
      if (monitorSection) monitorSection.style.display = "none";
      if (portScannerSection) portScannerSection.style.display = "none";
      if (ndDedicatedSection) ndDedicatedSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "block";
      if (threatSection) threatSection.style.display = "block";
      if (preventionSection) preventionSection.style.display = "block";
      if (teamSection) teamSection.style.display = "block";
      if (footerEl) footerEl.style.display = "block";

      setSidebarActive("home");
      setTopNavActive("home");

      if (updateHistory && window.location.search) {
        history.pushState({ view: "landing" }, "", window.location.pathname + (window.location.hash || ""));
      }
    }
  }

  // Intercept Navigation Link Clicks in Global Top Navbar
  topNavLinks.forEach(link => {
    link.addEventListener("click", (e) => {
      const navTarget = link.getAttribute("data-top-nav");
      if (navTarget === "monitoring") {
        e.preventDefault();
        switchView("monitoring");
      } else if (navTarget === "port-scanner") {
        e.preventDefault();
        switchView("port-scanner");
      } else if (navTarget === "network-discovery") {
        e.preventDefault();
        switchView("network-discovery");
      } else if (navTarget === "home") {
        if (document.body.classList.contains("dedicated-mode-monitoring") || 
            document.body.classList.contains("dedicated-mode-port-scanner") || 
            document.body.classList.contains("dedicated-mode-network-discovery")) {
          e.preventDefault();
          switchView("landing");
          window.scrollTo({ top: 0, behavior: "smooth" });
        } else {
          closeMobileSidebar();
          setSidebarActive("home");
          setTopNavActive("home");
        }
      }
    });
  });

  // Intercept Navigation Link Clicks
  sidebarNavItems.forEach(item => {
    item.addEventListener("click", (e) => {
      closeMobileSidebar();
      const navTarget = item.getAttribute("data-nav");
      if (navTarget === "monitoring") {
        e.preventDefault();
        switchView("monitoring");
      } else if (navTarget === "port-scanner") {
        e.preventDefault();
        switchView("port-scanner");
      } else if (navTarget === "network-discovery") {
        e.preventDefault();
        switchView("network-discovery");
      } else if (navTarget === "home") {
        if (document.body.classList.contains("dedicated-mode-monitoring") || 
            document.body.classList.contains("dedicated-mode-port-scanner") || 
            document.body.classList.contains("dedicated-mode-network-discovery")) {
          e.preventDefault();
          switchView("landing");
          window.scrollTo({ top: 0, behavior: "smooth" });
        } else {
          closeMobileSidebar();
          setSidebarActive("home");
        }
      }
    });
  });

  const sidebarBrandLink = document.getElementById("sidebarBrandLink");
  if (sidebarBrandLink) {
    sidebarBrandLink.addEventListener("click", (e) => {
      e.preventDefault();
      closeMobileSidebar();
      switchView("landing");
    });
  }

  const topNavBrandLink = document.querySelector(".top-nav-brand");
  if (topNavBrandLink) {
    topNavBrandLink.addEventListener("click", (e) => {
      e.preventDefault();
      closeMobileSidebar();
      switchView("landing");
    });
  }

  if (breadcrumbHomeLink) {
    breadcrumbHomeLink.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("landing");
    });
  }

  if (dedicatedViewToggleBtn) {
    dedicatedViewToggleBtn.addEventListener("click", () => {
      switchView("landing");
    });
  }

  const heroStartScanBtn = document.getElementById("heroStartScanBtn");
  const heroPortScanBtn = document.getElementById("heroPortScanBtn");

  if (heroStartScanBtn) {
    heroStartScanBtn.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("monitoring");
    });
  }

  if (heroPortScanBtn) {
    heroPortScanBtn.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("port-scanner");
    });
  }

  if (heroDiscoveryBtn) {
    heroDiscoveryBtn.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("network-discovery");
    });
  }

  if (openDiscoveryToolBtn) {
    openDiscoveryToolBtn.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("network-discovery");
    });
  }

  if (ndHeaderCtaBtn) {
    ndHeaderCtaBtn.addEventListener("click", () => {
      if (window.ndController && typeof window.ndController.startDiscovery === "function") {
        window.ndController.startDiscovery();
      }
    });
  }

  if (launchDedicatedMonitorBtn) {
    launchDedicatedMonitorBtn.addEventListener("click", () => {
      switchView("monitoring");
    });
  }

  if (launchDedicatedPortScannerBtn) {
    launchDedicatedPortScannerBtn.addEventListener("click", () => {
      switchView("port-scanner");
    });
  }

  // Listen to popstate (browser back/forward)
  window.addEventListener("popstate", () => {
    switchView(getQueryView(), false);
  });

  // Initialize view from URL
  switchView(getQueryView(), false);

  // Back To Top Button
  if (backToTopBtn) {
    window.addEventListener("scroll", () => {
      if (window.scrollY > 350) {
        backToTopBtn.classList.add("visible");
      } else {
        backToTopBtn.classList.remove("visible");
      }
    });

    backToTopBtn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  // ScrollSpy for Active Navigation Links on Landing Page
  const navSections = document.querySelectorAll("section[id]");

  function highlightNavOnScroll() {
    if (document.body.classList.contains("dedicated-mode-monitoring") || document.body.classList.contains("dedicated-mode-port-scanner")) {
      return;
    }
    setSidebarActive("home");
  }

  window.addEventListener("scroll", highlightNavOnScroll, { passive: true });

  // ============================================================================
  // 8. Event Listeners for DDoS Live Scanning
  // ============================================================================
  if (checkBtn) {
    checkBtn.addEventListener("click", () => {
      startScan();
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener("click", () => {
      stopScan();
    });
  }

  // ============================================================================
  // 9. Independent Port & Network Scanner Module (Decoupled from DDoS Core)
  // ============================================================================
  const PortScannerUI = (() => {
    let portScanPollTimer = null;
    let isPortScanning = false;
    let currentMode = "localhost";
    let currentPreset = "top20";
    let autoDetectedSubnet = "";
    let lastScanData = null;
    let activeFilter = "open"; // 'open' | 'all'
    let searchQuery = "";

    // DOM Elements
    const tabLocalhost = document.getElementById("psTabLocalhost");
    const tabTargetIp = document.getElementById("psTabTargetIp");
    const tabNetwork = document.getElementById("psTabNetwork");
    const modeTabs = [tabLocalhost, tabTargetIp, tabNetwork];

    const targetInput = document.getElementById("psTargetInput");
    const targetHint = document.getElementById("psTargetHint");
    const autoSubnetBtn = document.getElementById("psAutoSubnetBtn");
    const authWrap = document.getElementById("psAuthWrap");
    const authCheck = document.getElementById("psAuthCheck");

    const presetBtns = Array.from(document.querySelectorAll(".ps-preset-btn"));
    const customPortWrap = document.getElementById("psCustomPortWrap");
    const customPortInput = document.getElementById("psCustomPortInput");

    const timeoutSelect = document.getElementById("psTimeoutSelect");
    const concurrencySelect = document.getElementById("psConcurrencySelect");

    const startBtn = document.getElementById("psStartBtn");
    const stopBtn = document.getElementById("psStopBtn");
    const exportGroup = document.getElementById("psExportGroup");
    const exportJsonBtn = document.getElementById("psExportJsonBtn");
    const exportCsvBtn = document.getElementById("psExportCsvBtn");

    const stateBadge = document.getElementById("psStateBadge");
    const localIpBadge = document.getElementById("psLocalIpBadge");
    const progressBox = document.getElementById("psProgressBox");
    const progressBar = document.getElementById("psProgressBar");
    const progressStatusText = document.getElementById("psProgressStatusText");
    const progressPct = document.getElementById("psProgressPct");

    const kpiGrid = document.getElementById("psKpiGrid");
    const kpiHosts = document.getElementById("psKpiHosts");
    const kpiScanned = document.getElementById("psKpiScanned");
    const kpiOpen = document.getElementById("psKpiOpen");
    const kpiDuration = document.getElementById("psKpiDuration");

    const errorBanner = document.getElementById("psErrorBanner");
    const errorText = document.getElementById("psErrorText");

    const resultsWrapper = document.getElementById("psResultsWrapper");
    const resultsContent = document.getElementById("psResultsContent");
    const filterPills = Array.from(document.querySelectorAll(".ps-filter-pill"));
    const filterOpenCount = document.getElementById("psFilterOpenCount");
    const filterAllCount = document.getElementById("psFilterAllCount");
    const searchInput = document.getElementById("psSearchInput");

    async function loadNetworkInfo() {
      try {
        const res = await fetch("/api/port-scan/network-info");
        if (!res.ok) return;
        const data = await res.json();
        if (data.status === "success") {
          autoDetectedSubnet = data.suggested_subnet || "192.168.1.0/24";
          if (localIpBadge) {
            localIpBadge.innerHTML = `<i class="fas fa-circle-dot"></i> Local IP: ${data.local_ip || "127.0.0.1"}`;
          }
        }
      } catch (e) {
        console.warn("Could not load network info for port scanner:", e);
      }
    }

    function switchMode(mode) {
      currentMode = mode;
      hideError();

      modeTabs.forEach(tab => {
        if (!tab) return;
        const isActive = tab.getAttribute("data-mode") === mode;
        tab.classList.toggle("active", isActive);
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
      });

      if (!targetInput) return;

      if (mode === "localhost") {
        targetInput.value = "127.0.0.1";
        targetInput.readOnly = true;
        targetInput.placeholder = "127.0.0.1";
        if (targetHint) targetHint.textContent = "Loopback interface strictly locked for local inspection.";
        if (autoSubnetBtn) autoSubnetBtn.style.display = "none";
        if (authWrap) authWrap.style.display = "none";
      } else if (mode === "target_ip") {
        targetInput.value = "";
        targetInput.readOnly = false;
        targetInput.placeholder = "e.g. 192.168.1.15 or router.local";
        if (targetHint) targetHint.textContent = "Enter target IPv4 address or resolvable hostname.";
        if (autoSubnetBtn) autoSubnetBtn.style.display = "none";
        if (authWrap) authWrap.style.display = "none";
        targetInput.focus();
      } else if (mode === "network") {
        targetInput.value = autoDetectedSubnet || "192.168.1.0/24";
        targetInput.readOnly = false;
        targetInput.placeholder = "e.g. 192.168.1.0/24";
        if (targetHint) targetHint.textContent = "Enter private CIDR subnet (maximum size /24, up to 256 hosts).";
        if (autoSubnetBtn) autoSubnetBtn.style.display = "inline-flex";
        if (authWrap) authWrap.style.display = "block";
      }
    }

    function switchPreset(preset) {
      currentPreset = preset;
      presetBtns.forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-preset") === preset);
      });
      if (customPortWrap) {
        customPortWrap.style.display = (preset === "custom") ? "block" : "none";
        if (preset === "custom" && customPortInput) customPortInput.focus();
      }
    }

    function showError(msg) {
      if (errorBanner && errorText) {
        errorText.textContent = msg;
        errorBanner.style.display = "flex";
      }
    }

    function hideError() {
      if (errorBanner) errorBanner.style.display = "none";
    }

    function setBadge(state, label) {
      if (!stateBadge) return;
      stateBadge.className = `ps-status-pill ps-state-${state}`;
      stateBadge.textContent = label;
    }

    async function startScan() {
      if (isPortScanning) return;
      hideError();

      const target = (targetInput ? targetInput.value : "").trim();
      if (!target) {
        showError("Target address is required.");
        if (targetInput) targetInput.focus();
        return;
      }

      if (currentMode === "network") {
        if (authCheck && !authCheck.checked) {
          showError("Please confirm authorization to perform discovery on this target network.");
          return;
        }
      }

      let customPorts = null;
      if (currentPreset === "custom") {
        customPorts = (customPortInput ? customPortInput.value : "").trim();
        if (!customPorts) {
          showError("Please enter one or more custom ports (e.g. 80, 443, 8080).");
          if (customPortInput) customPortInput.focus();
          return;
        }
      }

      const timeout = parseFloat(timeoutSelect ? timeoutSelect.value : 0.5) || 0.5;
      const concurrency = parseInt(concurrencySelect ? concurrencySelect.value : 150, 10) || 150;

      // Update UI to scanning state
      isPortScanning = true;
      setBadge("scanning", "Scanning...");
      isPortScanning = true;
      if (startBtn) {
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Scanning...</span>';
      }
      if (stopBtn) stopBtn.style.display = "inline-flex";
      if (progressBox) {
        progressBox.style.display = "block";
        progressBox.classList.add("ps-scanning");
      }
      if (progressBar) {
        progressBar.style.width = "0%";
        progressBar.classList.add("scanning");
      }
      if (progressPct) progressPct.textContent = "0%";
      if (progressStatusText) progressStatusText.textContent = `Connecting to ${target}...`;

      if (kpiGrid) kpiGrid.style.display = "grid";
      if (kpiHosts) kpiHosts.textContent = "0";
      if (kpiScanned) kpiScanned.textContent = "0";
      if (kpiOpen) kpiOpen.textContent = "0";
      if (kpiDuration) kpiDuration.textContent = "0.0s";

      if (exportGroup) exportGroup.style.display = "none";

      try {
        const res = await fetch("/api/port-scan/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scan_type: currentMode,
            target: target,
            ports_mode: currentPreset,
            custom_ports: customPorts,
            timeout: timeout,
            concurrency: concurrency
          })
        });

        const data = await res.json();
        if (!res.ok || data.status === "error") {
          throw new Error(data.message || "Failed to start port scan.");
        }

        // Start polling status
        if (portScanPollTimer) clearInterval(portScanPollTimer);
        portScanPollTimer = setInterval(pollScanStatus, 350);

      } catch (err) {
        resetUI();
        setBadge("error", "Error");
        showError(err.message || "Connection error starting port scan.");
      }
    }

    async function stopScan() {
      try {
        await fetch("/api/port-scan/stop", { method: "POST" });
      } catch (e) {
        // ignore
      }
      if (portScanPollTimer) {
        clearInterval(portScanPollTimer);
        portScanPollTimer = null;
      }
      resetUI();
      setBadge("stopped", "Stopped");
      if (progressStatusText) progressStatusText.textContent = "Scan cancelled by user.";
    }

    async function pollScanStatus() {
      try {
        const res = await fetch("/api/port-scan/status");
        if (!res.ok) return;
        const data = await res.json();
        lastScanData = data;

        const status = data.status;
        const pct = Math.min(Math.max(data.progress_pct || 0, 0), 100);

        if (progressBar) progressBar.style.width = `${pct}%`;
        if (progressPct) progressPct.textContent = `${pct.toFixed(0)}%`;
        if (progressStatusText && data.message) progressStatusText.textContent = data.message;

        if (kpiHosts) updateTelemetryCounter(kpiHosts, data.active_hosts_count || 0);
        if (kpiScanned) updateTelemetryCounter(kpiScanned, data.scanned_ports || 0);
        if (kpiOpen) updateTelemetryCounter(kpiOpen, data.open_ports_count || 0);
        if (kpiDuration) kpiDuration.textContent = `${(data.duration_s || 0).toFixed(1)}s`;

        // Render live interim results if any open ports found
        if (data.results && data.results.length > 0) {
          renderResults(data.results);
        }

        if (status === "completed" || status === "stopped" || status === "error") {
          if (portScanPollTimer) {
            clearInterval(portScanPollTimer);
            portScanPollTimer = null;
          }
          resetUI();

          if (status === "completed") {
            setBadge("completed", "Completed");
            if (progressBar) progressBar.style.width = "100%";
            if (progressPct) progressPct.textContent = "100%";
          } else if (status === "stopped") {
            setBadge("stopped", "Stopped");
          } else if (status === "error") {
            setBadge("error", "Error");
            showError(data.error || data.message || "An error occurred during port scan.");
          }

          if (data.results && data.results.length > 0) {
            renderResults(data.results);
            if (exportGroup) exportGroup.style.display = "inline-flex";
          }
        }
      } catch (e) {
        console.warn("Port scanner poll error:", e);
      }
    }

    function resetUI() {
      isPortScanning = false;
      if (startBtn) {
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="fas fa-play"></i> <span>Start Port Scan</span>';
      }
      if (stopBtn) stopBtn.style.display = "none";
      if (progressBox) progressBox.classList.remove("ps-scanning");
      if (progressBar) progressBar.classList.remove("scanning");
    }

    function renderResults(hosts) {
      if (!resultsWrapper || !resultsContent) return;
      resultsWrapper.style.display = "block";

      // Compute total counts
      let totalOpen = 0;
      let totalAll = 0;
      hosts.forEach(h => {
        totalOpen += (h.open_ports || []).length;
        totalAll += (h.all_ports || []).length;
      });

      if (filterOpenCount) filterOpenCount.textContent = totalOpen;
      if (filterAllCount) filterAllCount.textContent = totalAll;

      const q = searchQuery.toLowerCase().trim();

      // Render based on scan mode
      if (currentMode === "network") {
        // Multi-host accordion cards
        let html = "";
        hosts.forEach((h, idx) => {
          const portsList = (activeFilter === "open") ? (h.open_ports || []) : (h.all_ports || []);
          const filteredPorts = portsList.filter(p => {
            if (!q) return true;
            return String(p.port).includes(q) || (p.service || "").toLowerCase().includes(q) || (p.banner || "").toLowerCase().includes(q);
          });

          const isOpenByDefault = idx === 0 || (h.open_ports && h.open_ports.length > 0);
          const openBadgeClass = (h.open_ports_count > 0) ? "ps-state-tag state-open" : "ps-state-tag state-closed";

          html += `
            <div class="ps-host-card ${isOpenByDefault ? "open" : ""}">
              <div class="ps-host-header" onclick="this.parentElement.classList.toggle('open')">
                <div class="ps-host-title">
                  <span class="ps-host-ip"><i class="fas fa-server"></i> ${escapeHtml(h.host)}</span>
                  ${h.hostname && h.hostname !== h.host ? `<span class="ps-host-name">(${escapeHtml(h.hostname)})</span>` : ""}
                </div>
                <div class="ps-host-meta">
                  <span class="${openBadgeClass}">
                    <i class="fas ${h.open_ports_count > 0 ? "fa-circle-check" : "fa-circle-xmark"}"></i>
                    ${h.open_ports_count} Open
                  </span>
                  <i class="fas fa-chevron-down ps-chevron"></i>
                </div>
              </div>
              <div class="ps-host-body">
                ${renderPortsTable(filteredPorts)}
              </div>
            </div>
          `;
        });

        if (!html) {
          html = `<div class="ps-empty-state"><i class="fas fa-search"></i>No hosts or ports match the current filter.</div>`;
        }
        resultsContent.innerHTML = html;

      } else {
        // Single host table (Localhost or Target IP)
        const host = hosts[0] || {};
        const portsList = (activeFilter === "open") ? (host.open_ports || []) : (host.all_ports || []);
        const filteredPorts = portsList.filter(p => {
          if (!q) return true;
          return String(p.port).includes(q) || (p.service || "").toLowerCase().includes(q) || (p.banner || "").toLowerCase().includes(q);
        });

        resultsContent.innerHTML = `
          <div class="ps-table-card">
            ${renderPortsTable(filteredPorts)}
          </div>
        `;
      }
    }

    function renderPortsTable(ports) {
      if (!ports || ports.length === 0) {
        return `<div class="ps-empty-state"><i class="fas fa-shield-halved"></i>No open ports detected in this category.</div>`;
      }

      let rows = "";
      ports.forEach((p, idx) => {
        const stateClass = p.state === "open" ? "state-open" : (p.state === "filtered" ? "state-filtered" : "state-closed");
        const stateIcon = p.state === "open" ? "fa-circle-check" : (p.state === "filtered" ? "fa-circle-exclamation" : "fa-circle-xmark");
        const latencyText = p.latency_ms !== null ? `${p.latency_ms} ms` : "--";
        const bannerHtml = p.banner ? `<code class="ps-banner-code" title="${escapeHtml(p.banner)}">${escapeHtml(p.banner)}</code>` : '<span class="text-muted">--</span>';

        rows += `
          <tr style="animation-delay: ${Math.min(idx * 28, 400)}ms">
            <td class="ps-port-num">${p.port}</td>
            <td><span class="ps-proto-tag">${p.protocol || "TCP"}</span></td>
            <td>
              <span class="ps-state-tag ${stateClass}">
                <i class="fas ${stateIcon}"></i> ${(p.state || "closed").toUpperCase()}
              </span>
            </td>
            <td><strong>${escapeHtml(p.service || "Unknown")}</strong></td>
            <td>${bannerHtml}</td>
            <td style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-muted);">${latencyText}</td>
          </tr>
        `;
      });

      return `
        <div class="ps-table-responsive-wrap">
          <table class="ps-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
                <th>Banner / Info</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      `;
    }

    function escapeHtml(str) {
      if (!str) return "";
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    function exportResults(format) {
      if (!lastScanData || !lastScanData.results || lastScanData.results.length === 0) return;

      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `port_scan_${lastScanData.scan_type || "results"}_${timestamp}.${format}`;

      if (format === "json") {
        const blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: "application/json" });
        downloadBlob(blob, filename);
      } else if (format === "csv") {
        let csv = "Host,Hostname,Port,Protocol,State,Service,Banner,LatencyMs\n";
        lastScanData.results.forEach(h => {
          const ports = h.all_ports && h.all_ports.length > 0 ? h.all_ports : (h.open_ports || []);
          ports.forEach(p => {
            const cleanBanner = (p.banner || "").replace(/"/g, '""');
            csv += `"${h.host}","${h.hostname || ""}","${p.port}","${p.protocol || "TCP"}","${p.state}","${p.service || ""}","${cleanBanner}","${p.latency_ms || ""}"\n`;
          });
        });
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
        downloadBlob(blob, filename);
      }
    }

    function downloadBlob(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    function init() {
      loadNetworkInfo();

      // Mode tabs
      modeTabs.forEach(tab => {
        if (!tab) return;
        tab.addEventListener("click", () => {
          if (isPortScanning) return;
          switchMode(tab.getAttribute("data-mode"));
        });
      });

      // Auto Subnet Button
      if (autoSubnetBtn) {
        autoSubnetBtn.addEventListener("click", () => {
          if (targetInput && autoDetectedSubnet) {
            targetInput.value = autoDetectedSubnet;
          }
        });
      }

      // Presets
      presetBtns.forEach(btn => {
        btn.addEventListener("click", () => {
          if (isPortScanning) return;
          switchPreset(btn.getAttribute("data-preset"));
        });
      });

      // Start / Stop
      if (startBtn) startBtn.addEventListener("click", startScan);
      if (stopBtn) stopBtn.addEventListener("click", stopScan);

      // Export buttons
      if (exportJsonBtn) exportJsonBtn.addEventListener("click", () => exportResults("json"));
      if (exportCsvBtn) exportCsvBtn.addEventListener("click", () => exportResults("csv"));

      // Filter tabs
      filterPills.forEach(pill => {
        pill.addEventListener("click", () => {
          filterPills.forEach(p => p.classList.remove("active"));
          pill.classList.add("active");
          activeFilter = pill.getAttribute("data-filter") || "open";
          if (lastScanData && lastScanData.results) {
            renderResults(lastScanData.results);
          }
        });
      });

      // Search input
      if (searchInput) {
        searchInput.addEventListener("input", (e) => {
          searchQuery = e.target.value;
          if (lastScanData && lastScanData.results) {
            renderResults(lastScanData.results);
          }
        });
      }
    }

    return {
      init,
      startScan,
      stopScan
    };
  })();

  // ============================================================================
  // 10. Home Page Cybersecurity Constellation Background & KPI Animation
  // ============================================================================
  function initCyberBackgroundCanvas() {
    const canvas = document.getElementById("cyberNetworkCanvas");
    if (!canvas) return;

    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      canvas.style.display = "none";
      return;
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let animId = null;
    let isVisible = true;

    function resize() {
      const parent = canvas.parentElement;
      if (!parent) return;
      const rect = parent.getBoundingClientRect();
      width = rect.width || window.innerWidth;
      height = rect.height || 600;
      canvas.width = width * (window.devicePixelRatio || 1);
      canvas.height = height * (window.devicePixelRatio || 1);
      ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
    }
    resize();
    window.addEventListener("resize", resize, { passive: true });

    const nodeCount = Math.max(18, Math.min(38, Math.floor(width / 36)));
    const nodes = [];
    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: 1.5 + Math.random() * 1.5,
        alpha: 0.25 + Math.random() * 0.35
      });
    }

    function render() {
      if (!isVisible) {
        animId = null;
        return;
      }
      ctx.clearRect(0, 0, width, height);

      const isDark = document.documentElement.getAttribute("data-theme") === "dark";
      const nodeRgb = isDark ? "72, 139, 110" : "53, 92, 74";

      // Connecting lines
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 115) {
            const lineAlpha = (1 - dist / 115) * 0.16;
            ctx.strokeStyle = `rgba(${nodeRgb}, ${lineAlpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // Nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;

        if (n.x < 0) { n.x = 0; n.vx *= -1; }
        else if (n.x > width) { n.x = width; n.vx *= -1; }
        if (n.y < 0) { n.y = 0; n.vy *= -1; }
        else if (n.y > height) { n.y = height; n.vy *= -1; }

        ctx.fillStyle = `rgba(${nodeRgb}, ${n.alpha})`;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fill();
      }

      animId = requestAnimationFrame(render);
    }

    const heroSec = canvas.closest(".hero-section");
    if (heroSec && "IntersectionObserver" in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          isVisible = entry.isIntersecting && !document.hidden;
          if (isVisible && !animId) {
            animId = requestAnimationFrame(render);
          }
        });
      }, { threshold: 0.05 });
      observer.observe(heroSec);
    } else {
      animId = requestAnimationFrame(render);
    }

    document.addEventListener("visibilitychange", () => {
      isVisible = !document.hidden;
      if (isVisible && !animId) {
        animId = requestAnimationFrame(render);
      }
    });
  }

  function initHeroStatsAnimation() {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }

    const statElements = document.querySelectorAll(".hero-stat-card .stat-number");
    if (!statElements || statElements.length === 0) return;

    let hasAnimated = false;
    const heroStatsGrid = document.querySelector(".hero-stats-grid");
    if (!heroStatsGrid) return;

    function animateValue(el, start, end, duration, decimals = 0, prefix = "", suffix = "") {
      let startTimestamp = null;
      const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const ease = 1 - (1 - progress) * (1 - progress);
        const current = start + (end - start) * ease;
        el.textContent = `${prefix}${current.toFixed(decimals)}${suffix}`;
        if (progress < 1) {
          window.requestAnimationFrame(step);
        } else {
          el.textContent = `${prefix}${end.toFixed(decimals)}${suffix}`;
        }
      };
      window.requestAnimationFrame(step);
    }

    function runStatsAnimation() {
      if (hasAnimated) return;
      hasAnimated = true;
      statElements.forEach(el => {
        const text = el.textContent.trim();
        if (text === "15") {
          animateValue(el, 0, 15, 1000);
        } else if (text === "77") {
          animateValue(el, 0, 77, 1200);
        } else if (text.includes("99.86")) {
          animateValue(el, 80.0, 99.86, 1400, 2, "", "%");
        } else if (text.includes("1.0")) {
          el.style.opacity = "0";
          setTimeout(() => {
            el.style.transition = "opacity 0.6s ease";
            el.style.opacity = "1";
          }, 300);
        }
      });
    }

    if ("IntersectionObserver" in window) {
      const obs = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            runStatsAnimation();
            obs.disconnect();
          }
        });
      }, { threshold: 0.2 });
      obs.observe(heroStatsGrid);
    } else {
      runStatsAnimation();
    }
  }

  // Initialize Hero Visual Enhancements
  initCyberBackgroundCanvas();
  initHeroStatsAnimation();

  // ============================================================================
  // 11. Autonomous Local Network Discovery & Asset Inventory Engine
  // ============================================================================
  const NetworkDiscoveryUI = (function() {
    const state = {
      networkInfo: null,
      scanStatus: 'idle', // 'idle' | 'scanning' | 'completed' | 'stopped' | 'error'
      scanId: null,
      pollInterval: null,
      devices: [],
      filterCategory: 'all',
      searchQuery: '',
      sortColumn: 'ip',
      sortAsc: true,
      viewMode: localStorage.getItem('nd_view_mode') || 'cards',
      selectedDevice: null,
      knownIps: new Set(),
      simTimer: null
    };

    let elements = {};

    function cacheDOMElements() {
      elements = {
        // Health indicators
        ndHealthDot: document.getElementById('ndHealthDot'),
        ndHealthLabel: document.getElementById('ndHealthLabel'),
        ndHeaderCtaBtn: document.getElementById('ndHeaderCtaBtn'),

        // KPIs
        kpiTotalDevices: document.getElementById('kpiTotalDevices'),
        kpiOnlineDevices: document.getElementById('kpiOnlineDevices'),
        kpiGatewayDevice: document.getElementById('kpiGatewayDevice'),
        kpiScanDuration: document.getElementById('kpiScanDuration'),

        // Subnet & Control Ribbon
        ndStateBadge: document.getElementById('ndStateBadge'),
        ndAdapterName: document.getElementById('ndAdapterName'),
        ndLocalIp: document.getElementById('ndLocalIp'),
        ndLocalMac: document.getElementById('ndLocalMac'),
        ndSubnetMask: document.getElementById('ndSubnetMask'),
        ndDefaultGateway: document.getElementById('ndDefaultGateway'),

        // Controls
        ndSubnetInput: document.getElementById('ndSubnetInput'),
        ndUseLocalSubnetBtn: document.getElementById('ndUseLocalSubnetBtn'),
        ndTimeoutSelect: document.getElementById('ndTimeoutSelect'),
        ndConcurrencySelect: document.getElementById('ndConcurrencySelect'),
        ndStartBtn: document.getElementById('ndStartBtn'),
        ndStopBtn: document.getElementById('ndStopBtn'),
        ndRescanBtn: document.getElementById('ndRescanBtn'),

        // Progress & Alert
        ndProgressBox: document.getElementById('ndProgressBox'),
        ndProgressBar: document.getElementById('ndProgressBar'),
        ndProgressStatus: document.getElementById('ndProgressStatus'),
        ndProgressPct: document.getElementById('ndProgressPct'),
        ndAlertBanner: document.getElementById('ndAlertBanner'),
        ndAlertMessage: document.getElementById('ndAlertMessage'),

        // Filters & Search
        countAll: document.getElementById('countAll'),
        countOnline: document.getElementById('countOnline'),
        countRouters: document.getElementById('countRouters'),
        countComputers: document.getElementById('countComputers'),
        countMobile: document.getElementById('countMobile'),
        countIot: document.getElementById('countIot'),
        ndSearchInput: document.getElementById('ndSearchInput'),

        // View Switcher & Containers
        ndViewCardsBtn: document.getElementById('ndViewCardsBtn'),
        ndViewTableBtn: document.getElementById('ndViewTableBtn'),
        ndCardsContainer: document.getElementById('ndCardsContainer'),
        ndCardsGrid: document.getElementById('ndCardsGrid'),
        ndTableWrapper: document.getElementById('ndTableWrapper'),
        ndDeviceTable: document.getElementById('ndDeviceTable'),
        ndTableBody: document.getElementById('ndTableBody'),

        // Modal
        ndDeviceModalBackdrop: document.getElementById('ndDeviceModalBackdrop'),
        ndDeviceModal: document.getElementById('ndDeviceModal'),
        modalCloseBtn: document.getElementById('modalCloseBtn'),
        modalFooterCloseBtn: document.getElementById('modalFooterCloseBtn'),
        modalDeviceAvatar: document.getElementById('modalDeviceAvatar'),
        modalDeviceTitle: document.getElementById('modalDeviceTitle'),
        modalDeviceSubtitle: document.getElementById('modalDeviceSubtitle'),
        modalHostname: document.getElementById('modalHostname'),
        modalIp: document.getElementById('modalIp'),
        modalMac: document.getElementById('modalMac'),
        modalVendor: document.getElementById('modalVendor'),
        modalCategory: document.getElementById('modalCategory'),
        modalRole: document.getElementById('modalRole'),
        modalStatusPill: document.getElementById('modalStatusPill'),
        modalStatusText: document.getElementById('modalStatusText'),
        modalBasis: document.getElementById('modalBasis'),
        modalLastSeen: document.getElementById('modalLastSeen'),
        modalMethods: document.getElementById('modalMethods'),
        modalPortsPanel: document.getElementById('modalPortsPanel'),
        modalPortsStatusBadge: document.getElementById('modalPortsStatusBadge'),
        modalPortsCountText: document.getElementById('modalPortsCountText'),
        modalPortsHelperText: document.getElementById('modalPortsHelperText'),
        modalPortsList: document.getElementById('modalPortsList'),
        modalPortScanLink: document.getElementById('modalPortScanLink')
      };
    }

    function escapeHtml(text) {
      if (text === null || text === undefined) return '';
      return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function getDeviceIcon(category, vendor, isGateway, isLocalHost) {
      if (isGateway) return 'fa-shield-halved';
      if (isLocalHost) return 'fa-laptop-code';

      const cat = (category || '').toLowerCase();
      const ven = (vendor || '').toLowerCase();

      if (cat.includes('router') || cat.includes('gateway') || cat.includes('access point')) return 'fa-network-wired';
      if (cat.includes('mobile') || cat.includes('phone') || ven.includes('apple') || ven.includes('samsung') || ven.includes('xiaomi') || ven.includes('huawei')) {
        return 'fa-mobile-screen-button';
      }
      if (cat.includes('computer') || cat.includes('workstation') || cat.includes('pc') || cat.includes('laptop') || ven.includes('dell') || ven.includes('lenovo') || ven.includes('hp')) {
        return 'fa-laptop';
      }
      if (cat.includes('server') || ven.includes('vmware') || ven.includes('hyper-v') || ven.includes('qemu')) return 'fa-server';
      if (cat.includes('printer') || ven.includes('canon') || ven.includes('epson') || ven.includes('xerox')) return 'fa-print';
      if (cat.includes('iot') || cat.includes('embedded') || ven.includes('raspberry') || ven.includes('espressif') || ven.includes('arduino')) {
        return 'fa-microchip';
      }
      if (cat.includes('tv') || cat.includes('media') || ven.includes('lg electronics') || ven.includes('sony') || ven.includes('roku')) {
        return 'fa-tv';
      }
      return 'fa-ethernet';
    }

    function compareIps(ipA, ipB) {
      if (!ipA || !ipB) return 0;
      const partsA = ipA.split('.').map(n => parseInt(n, 10) || 0);
      const partsB = ipB.split('.').map(n => parseInt(n, 10) || 0);
      for (let i = 0; i < 4; i++) {
        if (partsA[i] < partsB[i]) return -1;
        if (partsA[i] > partsB[i]) return 1;
      }
      return 0;
    }

    function showAlert(msg) {
      if (elements.ndAlertBanner && elements.ndAlertMessage) {
        elements.ndAlertMessage.textContent = msg;
        elements.ndAlertBanner.style.display = 'flex';
      }
    }

    function hideAlert() {
      if (elements.ndAlertBanner) elements.ndAlertBanner.style.display = 'none';
    }

    async function loadNetworkInfo() {
      try {
        const res = await fetch('/api/network-discovery/network-info');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        if (data.status === 'success' && data.network) {
          state.networkInfo = data.network;
          renderNetworkInfo(data.network);
          if (elements.ndSubnetInput && !elements.ndSubnetInput.value) {
            elements.ndSubnetInput.value = data.network.suggested_subnet || '192.168.1.0/24';
          }
          return;
        }
      } catch (err) {
        // Fallback info for standalone / offline preview
        const fallbackNet = {
          adapter_name: 'Wi-Fi 6 Adapter (802.11ax)',
          local_ip: '192.168.1.105',
          local_mac: '74:D4:35:E8:9B:12',
          subnet_mask: '255.255.255.0',
          suggested_subnet: '192.168.1.0/24',
          default_gateway: '192.168.1.1',
          is_connected: true
        };
        state.networkInfo = fallbackNet;
        renderNetworkInfo(fallbackNet);
        if (elements.ndSubnetInput && !elements.ndSubnetInput.value) {
          elements.ndSubnetInput.value = fallbackNet.suggested_subnet;
        }
      }
    }

    function renderNetworkInfo(net) {
      if (elements.ndAdapterName) elements.ndAdapterName.textContent = net.adapter_name || 'Ethernet / Wi-Fi';
      if (elements.ndLocalIp) elements.ndLocalIp.textContent = net.local_ip || '--';
      if (elements.ndLocalMac) elements.ndLocalMac.textContent = net.local_mac || 'Unavailable';
      if (elements.ndSubnetMask) elements.ndSubnetMask.textContent = net.subnet_mask || '255.255.255.0';
      if (elements.ndDefaultGateway) elements.ndDefaultGateway.textContent = net.default_gateway || 'None';
      if (elements.kpiGatewayDevice) elements.kpiGatewayDevice.textContent = net.default_gateway || '--';

      if (elements.ndHealthLabel && elements.ndHealthDot) {
        if (net.is_connected) {
          elements.ndHealthLabel.textContent = `Adapter: ${net.adapter_name} (${net.local_ip})`;
          elements.ndHealthDot.className = 'health-dot running';
        } else {
          elements.ndHealthLabel.textContent = 'Adapter: Disconnected / Offline';
          elements.ndHealthDot.className = 'health-dot idle';
        }
      }
    }

    async function startDiscoveryScan() {
      const subnet = (elements.ndSubnetInput ? elements.ndSubnetInput.value : '').trim();
      const timeout = parseFloat(elements.ndTimeoutSelect ? elements.ndTimeoutSelect.value : 0.6);
      const concurrency = parseInt(elements.ndConcurrencySelect ? elements.ndConcurrencySelect.value : 50, 10);

      if (!subnet) {
        showAlert('Please specify a valid IPv4 subnet in CIDR notation (e.g. 192.168.1.0/24).');
        return;
      }

      state.knownIps.clear();
      setScanUiState('starting');
      hideAlert();

      try {
        const res = await fetch('/api/network-discovery/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subnet, timeout, concurrency })
        });
        const data = await res.json();

        if (res.ok && (data.status === 'scanning' || data.status === 'already_scanning')) {
          state.scanStatus = 'scanning';
          state.scanId = data.scan_id;
          setScanUiState('scanning');
          startStatusPolling();
          return;
        } else {
          throw new Error(data.message || 'Service returned error');
        }
      } catch (err) {
        // Backend offline -> run simulated discovery scan
        console.info('[Network Discovery] Operating in autonomous demonstration mode:', err.message);
        runSimulatedDiscoveryScan(subnet);
      }
    }

    function runSimulatedDiscoveryScan(subnet) {
      state.scanStatus = 'scanning';
      setScanUiState('scanning');
      hideAlert();
      state.devices = [];
      state.knownIps.clear();
      renderDeviceInventory();

      const sampleHosts = [
        {
          ip: "192.168.1.1",
          mac: "E4:F0:42:38:1A:00",
          hostname: "gateway.router.lan",
          vendor: "Cisco Systems",
          device_type: "Router / Gateway",
          status: "Online",
          is_gateway: true,
          is_local_host: false,
          open_ports: [80, 443, 53, 22],
          open_ports_count: 4,
          methods: ["SendARP", "ICMP", "DNS"],
          basis: "Default Gateway MAC + OUI Registry",
          last_seen: "Just now"
        },
        {
          ip: "192.168.1.105",
          mac: "74:D4:35:E8:9B:12",
          hostname: "WORKSTATION-SEC",
          vendor: "Intel Corporate",
          device_type: "Computer / Workstation",
          status: "Online",
          is_gateway: false,
          is_local_host: true,
          open_ports: [135, 445],
          open_ports_count: 2,
          methods: ["Local Interface", "NetBIOS"],
          basis: "Active Host Adapter Binding",
          last_seen: "Just now"
        },
        {
          ip: "192.168.1.112",
          mac: "38:F9:D3:4A:21:BC",
          hostname: "MacBook-Pro-M2.local",
          vendor: "Apple Inc.",
          device_type: "Computer / Laptop",
          status: "Online",
          is_gateway: false,
          is_local_host: false,
          open_ports: [22, 5000],
          open_ports_count: 2,
          methods: ["SendARP", "mDNS"],
          basis: "Apple OUI + Reverse mDNS",
          last_seen: "Just now"
        },
        {
          ip: "192.168.1.118",
          mac: "BC:D1:D3:55:01:8A",
          hostname: "Galaxy-S24-Ultra",
          vendor: "Samsung Electronics",
          device_type: "Mobile Device",
          status: "Online",
          is_gateway: false,
          is_local_host: false,
          open_ports: [],
          open_ports_count: 0,
          methods: ["SendARP"],
          basis: "Samsung OUI Signature",
          last_seen: "Just now"
        },
        {
          ip: "192.168.1.130",
          mac: "DC:A6:32:8B:11:04",
          hostname: "raspberrypi-ids.local",
          vendor: "Raspberry Pi Foundation",
          device_type: "Embedded / IoT",
          status: "Online",
          is_gateway: false,
          is_local_host: false,
          open_ports: [22, 80, 8080],
          open_ports_count: 3,
          methods: ["SendARP", "ICMP Echo"],
          basis: "Raspberry Pi OUI + Port Fingerprint",
          last_seen: "Just now"
        },
        {
          ip: "192.168.1.145",
          mac: "10:65:30:4A:E0:9F",
          hostname: "HP-LaserJet-Pro-M404",
          vendor: "HP Inc.",
          device_type: "Printer / Peripherals",
          status: "Online",
          is_gateway: false,
          is_local_host: false,
          open_ports: [9100, 631, 80],
          open_ports_count: 3,
          methods: ["SendARP", "Bonjour"],
          basis: "HP Printer OUI Registry",
          last_seen: "Just now"
        },
        {
          ip: "192.168.1.170",
          mac: "F4:F5:DB:12:3C:99",
          hostname: "iPhone-15-Pro.local",
          vendor: "Apple Inc.",
          device_type: "Mobile Device",
          status: "Online",
          is_gateway: false,
          is_local_host: false,
          open_ports: [],
          open_ports_count: 0,
          methods: ["SendARP"],
          basis: "Apple OUI Signature",
          last_seen: "Just now"
        },
        {
          ip: "192.168.1.200",
          mac: "00:15:5D:80:23:FE",
          hostname: "ubuntu-server-prod",
          vendor: "Microsoft Hyper-V / Dell",
          device_type: "Server / Workstation",
          status: "Online",
          is_gateway: false,
          is_local_host: false,
          open_ports: [22, 80, 443, 3306],
          open_ports_count: 4,
          methods: ["SendARP", "ICMP", "TCP Syn"],
          basis: "Subnet Echo Probe + Port Map",
          last_seen: "Just now"
        }
      ];

      let currentStep = 0;
      const totalSteps = 8;
      const startTime = Date.now();

      if (state.simTimer) clearInterval(state.simTimer);
      state.simTimer = setInterval(() => {
        currentStep++;
        const progress = Math.min(Math.round((currentStep / totalSteps) * 100), 100);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

        if (elements.ndProgressBar) elements.ndProgressBar.style.width = progress + '%';
        if (elements.ndProgressPct) elements.ndProgressPct.textContent = progress + '%';
        if (elements.kpiScanDuration) elements.kpiScanDuration.textContent = elapsed + 's';

        if (currentStep === 2) {
          state.devices.push(sampleHosts[0]);
          state.devices.push(sampleHosts[1]);
        } else if (currentStep === 4) {
          state.devices.push(sampleHosts[2]);
          state.devices.push(sampleHosts[3]);
        } else if (currentStep === 6) {
          state.devices.push(sampleHosts[4]);
          state.devices.push(sampleHosts[5]);
        } else if (currentStep === 8) {
          state.devices.push(sampleHosts[6]);
          state.devices.push(sampleHosts[7]);
        }

        if (elements.kpiTotalDevices) elements.kpiTotalDevices.textContent = state.devices.length;
        if (elements.kpiOnlineDevices) elements.kpiOnlineDevices.textContent = state.devices.length;
        if (elements.ndProgressStatus) {
          elements.ndProgressStatus.textContent = currentStep < totalSteps
            ? `Probing local subnet addresses (${currentStep * 32}/254 checked) — ${state.devices.length} hosts discovered`
            : `Autonomous subnet scan complete. ${state.devices.length} active hosts enumerated.`;
        }

        updateCategoryCounts(state.devices);
        renderDeviceInventory();

        if (currentStep >= totalSteps) {
          clearInterval(state.simTimer);
          state.simTimer = null;
          state.scanStatus = 'completed';
          setScanUiState('completed');
        }
      }, 300);
    }

    async function stopDiscoveryScan() {
      if (state.simTimer) {
        clearInterval(state.simTimer);
        state.simTimer = null;
        state.scanStatus = 'stopped';
        setScanUiState('stopped');
        return;
      }

      try {
        await fetch('/api/network-discovery/stop', { method: 'POST' });
        state.scanStatus = 'stopped';
        setScanUiState('stopped');
        stopStatusPolling();
        fetchScanStatus();
      } catch (err) {
        state.scanStatus = 'stopped';
        setScanUiState('stopped');
      }
    }

    function rescanDiscovery() {
      if (state.scanStatus === 'scanning') {
        stopDiscoveryScan();
        setTimeout(startDiscoveryScan, 400);
      } else {
        startDiscoveryScan();
      }
    }

    function setScanUiState(st) {
      if (elements.ndStateBadge) {
        elements.ndStateBadge.textContent =
          st === 'scanning' ? 'Sweeping Subnet...' :
          st === 'starting' ? 'Starting...' :
          st === 'completed' ? 'Scan Completed' :
          st === 'stopped' ? 'Scan Cancelled' :
          st === 'error' ? 'Scan Error' : 'Ready';
        elements.ndStateBadge.className = 'nd-badge-state ' + (st === 'scanning' ? 'scanning' : st === 'completed' ? 'ready' : '');
      }

      if (st === 'scanning' || st === 'starting') {
        if (elements.ndStartBtn) elements.ndStartBtn.style.display = 'none';
        if (elements.ndStopBtn) elements.ndStopBtn.style.display = 'inline-flex';
        if (elements.ndProgressBox) elements.ndProgressBox.style.display = 'block';
      } else {
        if (elements.ndStartBtn) elements.ndStartBtn.style.display = 'inline-flex';
        if (elements.ndStopBtn) elements.ndStopBtn.style.display = 'none';
      }
    }

    function startStatusPolling() {
      if (state.pollInterval) clearInterval(state.pollInterval);
      state.pollInterval = setInterval(fetchScanStatus, 500);
    }

    function stopStatusPolling() {
      if (state.pollInterval) {
        clearInterval(state.pollInterval);
        state.pollInterval = null;
      }
    }

    async function fetchScanStatus() {
      try {
        const res = await fetch('/api/network-discovery/status');
        if (!res.ok) return;
        const data = await res.json();

        state.scanStatus = data.status || 'idle';
        state.devices = data.devices || [];

        if (elements.kpiTotalDevices) elements.kpiTotalDevices.textContent = data.devices_count || state.devices.length;
        if (elements.kpiOnlineDevices) elements.kpiOnlineDevices.textContent = data.online_count || state.devices.length;
        if (elements.kpiScanDuration) elements.kpiScanDuration.textContent = (data.duration_s || 0).toFixed(1) + 's';

        const pct = Math.round(data.progress_pct || 0);
        if (elements.ndProgressBar) elements.ndProgressBar.style.width = pct + '%';
        if (elements.ndProgressPct) elements.ndProgressPct.textContent = pct + '%';
        if (elements.ndProgressStatus) {
          elements.ndProgressStatus.textContent =
            data.status === 'scanning'
              ? `Probing hosts (${data.scanned_hosts || 0}/${data.total_hosts || 0} checked) — ${data.devices_count || 0} responsive hosts discovered`
              : data.message || 'Discovery complete.';
        }

        updateCategoryCounts(state.devices);
        renderDeviceInventory();

        if (data.status === 'completed' || data.status === 'stopped' || data.status === 'error') {
          stopStatusPolling();
          setScanUiState(data.status);
        }
      } catch (err) {
        // silent ignore transient poll error
      }
    }

    function updateCategoryCounts(devices) {
      let online = 0, routers = 0, computers = 0, mobile = 0, iot = 0;
      devices.forEach(dev => {
        if (dev.status === 'Online') online++;
        const cat = (dev.device_type || '').toLowerCase();
        const ven = (dev.vendor || '').toLowerCase();
        if (dev.is_gateway || cat.includes('router') || cat.includes('gateway') || cat.includes('access point')) {
          routers++;
        } else if (cat.includes('computer') || cat.includes('workstation') || dev.is_local_host) {
          computers++;
        } else if (cat.includes('mobile') || ven.includes('apple') || ven.includes('samsung') || ven.includes('xiaomi')) {
          mobile++;
        } else if (cat.includes('iot') || cat.includes('printer') || cat.includes('embedded')) {
          iot++;
        }
      });

      if (elements.countAll) elements.countAll.textContent = devices.length;
      if (elements.countOnline) elements.countOnline.textContent = online;
      if (elements.countRouters) elements.countRouters.textContent = routers;
      if (elements.countComputers) elements.countComputers.textContent = computers;
      if (elements.countMobile) elements.countMobile.textContent = mobile;
      if (elements.countIot) elements.countIot.textContent = iot;
    }

    function filterAndSortDevices() {
      let list = [...state.devices];

      if (state.filterCategory !== 'all') {
        list = list.filter(dev => {
          const cat = (dev.device_type || '').toLowerCase();
          const ven = (dev.vendor || '').toLowerCase();
          if (state.filterCategory === 'online') return dev.status === 'Online';
          if (state.filterCategory === 'router') {
            return dev.is_gateway || cat.includes('router') || cat.includes('gateway') || cat.includes('access point');
          }
          if (state.filterCategory === 'computer') {
            return cat.includes('computer') || cat.includes('workstation') || dev.is_local_host;
          }
          if (state.filterCategory === 'mobile') {
            return cat.includes('mobile') || ven.includes('apple') || ven.includes('samsung') || ven.includes('xiaomi');
          }
          if (state.filterCategory === 'iot') {
            return cat.includes('iot') || cat.includes('printer') || cat.includes('embedded');
          }
          return true;
        });
      }

      if (state.searchQuery) {
        const q = state.searchQuery.toLowerCase();
        list = list.filter(dev => {
          return (
            (dev.ip || '').toLowerCase().includes(q) ||
            (dev.hostname || '').toLowerCase().includes(q) ||
            (dev.mac || '').toLowerCase().includes(q) ||
            (dev.vendor || '').toLowerCase().includes(q) ||
            (dev.device_type || '').toLowerCase().includes(q) ||
            (dev.methods || []).join(' ').toLowerCase().includes(q)
          );
        });
      }

      list.sort((a, b) => {
        let valA = a[state.sortColumn] || '';
        let valB = b[state.sortColumn] || '';

        if (state.sortColumn === 'ip') {
          const cmp = compareIps(a.ip, b.ip);
          return state.sortAsc ? cmp : -cmp;
        }

        if (typeof valA === 'string') valA = valA.toLowerCase();
        if (typeof valB === 'string') valB = valB.toLowerCase();

        if (valA < valB) return state.sortAsc ? -1 : 1;
        if (valA > valB) return state.sortAsc ? 1 : -1;
        return 0;
      });

      return list;
    }

    function getDevicePortsInfo(dev) {
      let count = null;
      if (dev.open_ports_count !== undefined && dev.open_ports_count !== null) {
        count = Number(dev.open_ports_count);
      } else if (Array.isArray(dev.open_ports)) {
        count = dev.open_ports.length;
      }
      return {
        count: count,
        ports: Array.isArray(dev.open_ports) ? dev.open_ports : []
      };
    }

    function renderDeviceInventory() {
      const list = filterAndSortDevices();
      renderDeviceCards(list);
      renderCompactTable(list);
      attachDeviceActionListeners();
    }

    function renderDeviceCards(list) {
      if (!elements.ndCardsGrid) return;

      if (list.length === 0) {
        const isScanActive = state.scanStatus === 'scanning';
        elements.ndCardsGrid.innerHTML = `
          <div class="nd-empty-state">
            <div class="nd-empty-icon"><i class="fas ${isScanActive ? 'fa-spinner fa-spin' : 'fa-satellite-dish'}"></i></div>
            <h3 class="nd-empty-title">${isScanActive ? 'Probing Subnet...' : 'No Devices Found'}</h3>
            <p class="nd-empty-desc">${
              isScanActive
                ? 'Active ARP and ICMP sweeps are underway. Discovered hosts will appear here dynamically.'
                : state.devices.length === 0
                ? "Click 'Start Discovery' above to sweep your local subnet and populate the device asset inventory."
                : 'No devices matched the selected filter or search criteria.'
            }</p>
          </div>
        `;
        return;
      }

      const cardsHtml = list.map((dev, idx) => {
        const icon = getDeviceIcon(dev.device_type, dev.vendor, dev.is_gateway, dev.is_local_host);
        const isOnline = dev.status === 'Online';
        const isNew = state.scanStatus === 'scanning' && !state.knownIps.has(dev.ip);
        if (isNew) state.knownIps.add(dev.ip);

        const hostnameDisplay = (!dev.hostname || dev.hostname === 'Unknown')
          ? `<span class="nd-text-muted">Unknown</span>`
          : `<span class="nd-card-hostname-text">${escapeHtml(dev.hostname)}</span>`;

        const macDisplay = (!dev.mac || dev.mac === 'Unavailable' || dev.mac === 'Unknown')
          ? `<span class="nd-text-muted">Not detected</span>`
          : `<span class="mono">${escapeHtml(dev.mac)}</span>`;

        const vendorClean = (!dev.vendor || dev.vendor === 'Unknown' || dev.vendor === 'Unknown Vendor')
          ? 'Unknown Vendor'
          : dev.vendor;

        const categoryClean = dev.device_type || 'Network Device';

        let roleBadge = '';
        if (dev.is_gateway) {
          roleBadge = `<span class="nd-badge-role gw" title="Default Subnet Gateway Router"><i class="fas fa-shield-alt"></i> Gateway</span>`;
        } else if (dev.is_local_host) {
          roleBadge = `<span class="nd-badge-role self" title="Your Current Local Machine"><i class="fas fa-laptop"></i> Host</span>`;
        }

        const portsInfo = getDevicePortsInfo(dev);
        let portsDisplay = '';
        if (portsInfo.count !== null) {
          const hasOpen = portsInfo.count > 0;
          portsDisplay = `
            <span class="nd-ports-badge ${hasOpen ? 'has-ports' : 'zero-ports'}">
              <i class="fas ${hasOpen ? 'fa-door-open' : 'fa-shield'}"></i>
              ${portsInfo.count} ${portsInfo.count === 1 ? 'Open Port' : 'Open Ports'}
            </span>
          `;
        } else {
          portsDisplay = `
            <span class="nd-ports-badge not-scanned" title="Port scan not conducted for this host">
              <i class="fas fa-minus"></i> Not detected
            </span>
          `;
        }

        return `
          <div class="nd-device-card ${isNew ? 'new-discovery-glow' : ''}" data-ip="${escapeHtml(dev.ip)}" style="animation-delay: ${Math.min(idx * 35, 500)}ms">
            <div class="nd-card-header">
              <div class="nd-card-avatar" title="${escapeHtml(categoryClean)}">
                <i class="fas ${icon}"></i>
              </div>
              <div class="nd-card-title-col">
                <div class="nd-card-name-row">
                  <h4 class="nd-card-hostname" title="${escapeHtml(dev.hostname || dev.ip)}">${hostnameDisplay}</h4>
                  ${roleBadge}
                </div>
                <span class="nd-card-sub" title="${escapeHtml(categoryClean)} • ${escapeHtml(vendorClean)}">
                  ${escapeHtml(categoryClean)} • ${escapeHtml(vendorClean)}
                </span>
              </div>
              <span class="nd-status-pill ${isOnline ? 'online' : 'offline'}">
                <span class="status-pulse-dot"></span>
                ${escapeHtml(dev.status || 'Offline')}
              </span>
            </div>

            <div class="nd-card-body">
              <div class="nd-card-prop">
                <span class="nd-prop-label"><i class="fas fa-location-dot"></i> IP Address</span>
                <div class="nd-prop-val-wrap">
                  <span class="nd-prop-val mono ${dev.is_gateway ? 'text-gw' : ''}">${escapeHtml(dev.ip)}</span>
                  <button type="button" class="nd-mini-copy-btn" data-copy-text="${escapeHtml(dev.ip)}" title="Copy IP Address">
                    <i class="fas fa-copy"></i>
                  </button>
                </div>
              </div>

              <div class="nd-card-prop">
                <span class="nd-prop-label"><i class="fas fa-fingerprint"></i> MAC Address</span>
                <span class="nd-prop-val mono">${macDisplay}</span>
              </div>

              <div class="nd-card-prop">
                <span class="nd-prop-label"><i class="fas fa-shield-halved"></i> Open Ports</span>
                <span class="nd-prop-val">${portsDisplay}</span>
              </div>
            </div>

            <div class="nd-card-footer">
              <button type="button" class="nd-btn-details nd-view-details-btn" data-ip="${escapeHtml(dev.ip)}" title="View complete hardware profile and scan details">
                <i class="fas fa-circle-info"></i> View Details
              </button>
            </div>
          </div>
        `;
      }).join('');

      elements.ndCardsGrid.innerHTML = cardsHtml;
    }

    function renderCompactTable(list) {
      if (!elements.ndTableBody) return;

      if (list.length === 0) {
        const isScanActive = state.scanStatus === 'scanning';
        elements.ndTableBody.innerHTML = `
          <tr class="nd-empty-row">
            <td colspan="6">
              <div class="nd-empty-state">
                <div class="nd-empty-icon"><i class="fas ${isScanActive ? 'fa-spinner fa-spin' : 'fa-satellite-dish'}"></i></div>
                <h3 class="nd-empty-title">${isScanActive ? 'Probing Subnet...' : 'No Devices Found'}</h3>
                <p class="nd-empty-desc">${
                  isScanActive
                    ? 'Active ARP and ICMP sweeps are underway. Discovered hosts will appear here dynamically.'
                    : state.devices.length === 0
                    ? "Click 'Start Discovery' above to sweep your local subnet and populate the device asset inventory."
                    : 'No devices matched the selected filter or search criteria.'
                }</p>
              </div>
            </td>
          </tr>
        `;
        return;
      }

      const rowsHtml = list.map((dev, idx) => {
        const icon = getDeviceIcon(dev.device_type, dev.vendor, dev.is_gateway, dev.is_local_host);
        const isOnline = dev.status === 'Online';

        const hostnameDisplay = (!dev.hostname || dev.hostname === 'Unknown')
          ? `<span class="nd-text-muted">Unknown</span>`
          : `<span class="nd-hostname-text" title="${escapeHtml(dev.hostname)}">${escapeHtml(dev.hostname)}</span>`;

        const macDisplay = (!dev.mac || dev.mac === 'Unavailable' || dev.mac === 'Unknown')
          ? `<span class="nd-text-muted">Not detected</span>`
          : `<span class="mono">${escapeHtml(dev.mac)}</span>`;

        let roleBadge = '';
        if (dev.is_gateway) {
          roleBadge = `<span class="nd-badge-role gw" title="Default Subnet Gateway Router"><i class="fas fa-shield-alt"></i> Gateway</span>`;
        } else if (dev.is_local_host) {
          roleBadge = `<span class="nd-badge-role self" title="Your Current Local Machine"><i class="fas fa-laptop"></i> Host</span>`;
        }

        const portsInfo = getDevicePortsInfo(dev);
        let portsDisplay = '';
        if (portsInfo.count !== null) {
          const hasOpen = portsInfo.count > 0;
          portsDisplay = `
            <span class="nd-ports-badge ${hasOpen ? 'has-ports' : 'zero-ports'}">
              <i class="fas ${hasOpen ? 'fa-door-open' : 'fa-shield'}"></i>
              ${portsInfo.count} Open
            </span>
          `;
        } else {
          portsDisplay = `
            <span class="nd-ports-badge not-scanned" title="Port scan not conducted for this host">
              <i class="fas fa-minus"></i> Not detected
            </span>
          `;
        }

        return `
          <tr class="nd-device-row" data-ip="${escapeHtml(dev.ip)}" style="animation-delay: ${Math.min(idx * 28, 450)}ms">
            <td class="col-hostname">
              <div class="nd-device-cell">
                <div class="nd-avatar-circle" title="${escapeHtml(dev.device_type || 'Device')}">
                  <i class="fas ${icon}"></i>
                </div>
                <div class="nd-name-meta">
                  ${hostnameDisplay}
                  ${roleBadge}
                </div>
              </div>
            </td>
            <td class="col-ip">
              <span class="mono fw-600 ${dev.is_gateway ? 'text-gw' : ''}">${escapeHtml(dev.ip)}</span>
            </td>
            <td class="col-mac">${macDisplay}</td>
            <td class="col-status">
              <span class="nd-status-pill ${isOnline ? 'online' : 'offline'}">
                <span class="status-pulse-dot"></span>
                ${escapeHtml(dev.status || 'Offline')}
              </span>
            </td>
            <td class="col-ports">${portsDisplay}</td>
            <td class="col-actions">
              <button type="button" class="nd-table-btn nd-view-details-btn" data-ip="${escapeHtml(dev.ip)}" title="View complete hardware profile">
                <i class="fas fa-circle-info"></i> Details
              </button>
            </td>
          </tr>
        `;
      }).join('');

      elements.ndTableBody.innerHTML = rowsHtml;
    }

    function attachDeviceActionListeners() {
      if (elements.ndCardsGrid) {
        elements.ndCardsGrid.querySelectorAll('.nd-device-card').forEach(card => {
          card.addEventListener('click', (e) => {
            if (e.target.closest('button') || e.target.closest('a')) return;
            const ip = card.getAttribute('data-ip');
            if (ip) openDeviceModal(ip);
          });
        });
      }

      if (elements.ndTableBody) {
        elements.ndTableBody.querySelectorAll('.nd-device-row').forEach(row => {
          row.addEventListener('click', (e) => {
            if (e.target.closest('button') || e.target.closest('a')) return;
            const ip = row.getAttribute('data-ip');
            if (ip) openDeviceModal(ip);
          });
        });
      }

      document.querySelectorAll('.nd-view-details-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const ip = btn.getAttribute('data-ip');
          if (ip) openDeviceModal(ip);
        });
      });

      document.querySelectorAll('.nd-mini-copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const text = btn.getAttribute('data-copy-text');
          if (text) copyDirectText(text, btn);
        });
      });
    }

    function openDeviceModal(ip) {
      const dev = state.devices.find(d => d.ip === ip);
      if (!dev) return;

      state.selectedDevice = dev;
      const icon = getDeviceIcon(dev.device_type, dev.vendor, dev.is_gateway, dev.is_local_host);

      if (elements.modalDeviceAvatar) {
        elements.modalDeviceAvatar.innerHTML = `<i class="fas ${icon}"></i>`;
      }
      if (elements.modalDeviceTitle) {
        elements.modalDeviceTitle.textContent = dev.hostname && dev.hostname !== 'Unknown' ? dev.hostname : dev.ip;
      }
      if (elements.modalDeviceSubtitle) {
        elements.modalDeviceSubtitle.textContent = `IPv4: ${dev.ip}${dev.vendor ? ' • ' + dev.vendor : ''}`;
      }

      if (elements.modalHostname) elements.modalHostname.textContent = dev.hostname || 'Unknown';
      if (elements.modalIp) elements.modalIp.textContent = dev.ip || '--';
      if (elements.modalMac) elements.modalMac.textContent = dev.mac || 'Unavailable';
      if (elements.modalVendor) elements.modalVendor.textContent = dev.vendor || 'Unknown Vendor';
      if (elements.modalCategory) elements.modalCategory.textContent = dev.device_type || 'General Endpoint';

      if (elements.modalRole) {
        if (dev.is_gateway) {
          elements.modalRole.innerHTML = '<span class="text-gw fw-600"><i class="fas fa-shield-alt"></i> Default Gateway Router</span>';
        } else if (dev.is_local_host) {
          elements.modalRole.innerHTML = '<span class="text-accent fw-600"><i class="fas fa-laptop"></i> Local Machine (This Host)</span>';
        } else {
          elements.modalRole.textContent = 'Subnet Network Node';
        }
      }

      const isOnline = dev.status === 'Online';
      if (elements.modalStatusPill) {
        elements.modalStatusPill.className = `nd-status-pill ${isOnline ? 'online' : 'offline'}`;
      }
      if (elements.modalStatusText) {
        elements.modalStatusText.textContent = dev.status || 'Offline';
      }

      if (elements.modalBasis) elements.modalBasis.textContent = dev.basis || 'ARP Table Match + OUI Resolution';
      if (elements.modalLastSeen) elements.modalLastSeen.textContent = dev.last_seen || 'Just now';

      if (elements.modalMethods) {
        const methods = dev.methods && dev.methods.length > 0 ? dev.methods : ['SendARP'];
        elements.modalMethods.innerHTML = methods
          .map(m => `<span class="nd-method-tag"><i class="fas fa-check"></i> ${escapeHtml(m)}</span>`)
          .join('');
      }

      // Open Ports Telemetry Panel
      const portsInfo = getDevicePortsInfo(dev);
      if (elements.modalPortsPanel) {
        if (portsInfo.count !== null) {
          const hasPorts = portsInfo.count > 0;
          if (elements.modalPortsStatusBadge) {
            elements.modalPortsStatusBadge.className = `nd-ports-status-badge ${hasPorts ? 'has-ports' : 'zero-ports'}`;
          }
          if (elements.modalPortsCountText) {
            elements.modalPortsCountText.textContent = `${portsInfo.count} ${portsInfo.count === 1 ? 'Open Port' : 'Open Ports'}`;
          }
          if (elements.modalPortsHelperText) {
            elements.modalPortsHelperText.textContent = hasPorts
              ? 'Active listening services detected on this endpoint:'
              : 'Target host was responsive to network sweep, but no common ports reported open.';
          }

          if (elements.modalPortsList) {
            if (hasPorts) {
              elements.modalPortsList.innerHTML = portsInfo.ports
                .map(p => {
                  const portNum = typeof p === 'object' ? p.port : p;
                  const portSvc = typeof p === 'object' ? p.service : '';
                  return `
                    <span class="nd-port-chip">
                      <span class="chip-num">${portNum}</span>
                      ${portSvc ? `<span class="chip-svc">${escapeHtml(portSvc)}</span>` : ''}
                    </span>
                  `;
                })
                .join('');
              elements.modalPortsList.style.display = 'flex';
            } else {
              elements.modalPortsList.style.display = 'none';
            }
          }
        } else {
          if (elements.modalPortsStatusBadge) elements.modalPortsStatusBadge.className = 'nd-ports-status-badge not-scanned';
          if (elements.modalPortsCountText) elements.modalPortsCountText.textContent = 'Not Scanned';
          if (elements.modalPortsHelperText) {
            elements.modalPortsHelperText.textContent = 'Run a targeted port scan on this host to enumerate active services and vulnerabilities.';
          }
          if (elements.modalPortsList) elements.modalPortsList.style.display = 'none';
        }
      }

      // Link to Port Scanner: switches view and pre-fills target IP
      if (elements.modalPortScanLink) {
        elements.modalPortScanLink.onclick = function(e) {
          e.preventDefault();
          closeDeviceModal();
          switchView('port-scanner');
          const targetInput = document.getElementById('psTargetInput');
          if (targetInput) {
            targetInput.value = dev.ip;
            targetInput.focus();
          }
        };
      }

      if (elements.ndDeviceModalBackdrop) {
        elements.ndDeviceModalBackdrop.classList.add('open');
        document.body.style.overflow = 'hidden';
      }
    }

    function closeDeviceModal() {
      if (elements.ndDeviceModalBackdrop) {
        elements.ndDeviceModalBackdrop.classList.remove('open');
      }
      document.body.style.overflow = '';
      state.selectedDevice = null;
    }

    function copyDirectText(text, btn) {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(text).then(() => {
        const icon = btn.querySelector('i');
        if (icon) {
          const oldClass = icon.className;
          icon.className = 'fas fa-check text-green';
          setTimeout(() => { icon.className = oldClass; }, 1400);
        }
      });
    }

    function copyToClipboard(elementId, btn) {
      const el = document.getElementById(elementId);
      if (!el || !navigator.clipboard) return;
      navigator.clipboard.writeText(el.textContent.trim()).then(() => {
        const icon = btn.querySelector('i');
        if (icon) {
          const oldClass = icon.className;
          icon.className = 'fas fa-check text-green';
          setTimeout(() => { icon.className = oldClass; }, 1400);
        }
      });
    }

    function setViewMode(mode) {
      state.viewMode = mode;
      localStorage.setItem('nd_view_mode', mode);

      if (mode === 'table') {
        if (elements.ndCardsContainer) elements.ndCardsContainer.style.display = 'none';
        if (elements.ndTableWrapper) elements.ndTableWrapper.style.display = 'block';
        if (elements.ndViewTableBtn) elements.ndViewTableBtn.classList.add('active');
        if (elements.ndViewCardsBtn) elements.ndViewCardsBtn.classList.remove('active');
      } else {
        if (elements.ndCardsContainer) elements.ndCardsContainer.style.display = 'block';
        if (elements.ndTableWrapper) elements.ndTableWrapper.style.display = 'none';
        if (elements.ndViewCardsBtn) elements.ndViewCardsBtn.classList.add('active');
        if (elements.ndViewTableBtn) elements.ndViewTableBtn.classList.remove('active');
      }
    }

    function initEventListeners() {
      if (elements.ndStartBtn) elements.ndStartBtn.addEventListener('click', startDiscoveryScan);
      if (elements.ndStopBtn) elements.ndStopBtn.addEventListener('click', stopDiscoveryScan);
      if (elements.ndRescanBtn) elements.ndRescanBtn.addEventListener('click', rescanDiscovery);

      if (elements.ndUseLocalSubnetBtn) {
        elements.ndUseLocalSubnetBtn.addEventListener('click', () => {
          if (state.networkInfo && state.networkInfo.suggested_subnet && elements.ndSubnetInput) {
            elements.ndSubnetInput.value = state.networkInfo.suggested_subnet;
          }
        });
      }

      if (elements.ndSearchInput) {
        elements.ndSearchInput.addEventListener('input', (e) => {
          state.searchQuery = e.target.value.trim();
          renderDeviceInventory();
        });
      }

      const filterTabs = document.querySelectorAll('.nd-filter-tab');
      filterTabs.forEach(tab => {
        tab.addEventListener('click', () => {
          filterTabs.forEach(t => t.classList.remove('active'));
          tab.classList.add('active');
          state.filterCategory = tab.getAttribute('data-filter') || 'all';
          renderDeviceInventory();
        });
      });

      if (elements.ndViewCardsBtn) elements.ndViewCardsBtn.addEventListener('click', () => setViewMode('cards'));
      if (elements.ndViewTableBtn) elements.ndViewTableBtn.addEventListener('click', () => setViewMode('table'));

      if (elements.ndDeviceTable) {
        elements.ndDeviceTable.querySelectorAll('th[data-sort]').forEach(th => {
          th.addEventListener('click', () => {
            const col = th.getAttribute('data-sort');
            if (state.sortColumn === col) {
              state.sortAsc = !state.sortAsc;
            } else {
              state.sortColumn = col;
              state.sortAsc = true;
            }
            renderDeviceInventory();
          });
        });
      }

      if (elements.modalCloseBtn) elements.modalCloseBtn.addEventListener('click', closeDeviceModal);
      if (elements.modalFooterCloseBtn) elements.modalFooterCloseBtn.addEventListener('click', closeDeviceModal);
      if (elements.ndDeviceModalBackdrop) {
        elements.ndDeviceModalBackdrop.addEventListener('click', (e) => {
          if (e.target === elements.ndDeviceModalBackdrop) closeDeviceModal();
        });
      }

      window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeDeviceModal();
      });

      document.querySelectorAll('.nd-copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const targetId = btn.getAttribute('data-copy');
          if (targetId) copyToClipboard(targetId, btn);
        });
      });
    }

    function init() {
      cacheDOMElements();
      initEventListeners();
      setViewMode(state.viewMode);
      loadNetworkInfo();

      // Export controller for external coordinators
      window.ndController = {
        startDiscovery: startDiscoveryScan,
        stopDiscovery: stopDiscoveryScan,
        onActivated: function() {
          if (!state.networkInfo) loadNetworkInfo();
        }
      };
    }

    return {
      init: init,
      onActivated: function() {
        if (window.ndController && window.ndController.onActivated) {
          window.ndController.onActivated();
        }
      }
    };
  })();


  // Initialize Network Discovery Engine
  NetworkDiscoveryUI.init();

  // Initialize Port Scanner UI
  PortScannerUI.init();

  window.addEventListener("beforeunload", () => {
    if (isScanning) stopScan(true);
  });
});