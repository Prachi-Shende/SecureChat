import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  Send, Shield, Lock, Activity, AlertTriangle, RefreshCw,
  Search, MoreVertical, ShieldCheck, Key, Zap, Layers,
  Database, UserCheck, MessageSquare, BarChart3, ChevronDown,
  Cpu, HardDrive, Network, Table, PieChart, Info, CheckCircle2,
  XCircle, Beaker, FileText, Globe
} from 'lucide-react';


const API_BASE = "http://localhost:8000";

const App = () => {
  const [messages, setMessages] = useState([]);
  const [eccMessages, setEccMessages] = useState([]);
  const [aeadMessages, setAeadMessages] = useState([]);
  const [selectedMsg, setSelectedMsg] = useState(null);
  const [inputText, setInputText] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeSender, setActiveSender] = useState("ALICE");
  const [isSimulating, setIsSimulating] = useState(false);
  const [isAutoPlaying, setIsAutoPlaying] = useState(true);
  const [simData, setSimData] = useState(null);
  const [simStep, setSimStep] = useState(0);
  const [systemMode, setSystemMode] = useState("CLASSIC"); // "CLASSIC", "ECC_CBC", or "AEAD"
  const [benchmarkResults, setBenchmarkResults] = useState(null);
  const [showBenchmark, setShowBenchmark] = useState(false);
  const [showAnalysis, setShowAnalysis] = useState(false);
  const [labTab, setLabTab] = useState("DASHBOARD"); // DASHBOARD, PERFORMANCE, SECURITY, STATISTICAL
  const [experimentResults, setExperimentResults] = useState(null);
  const [labLoading, setLabLoading] = useState(false);
  
  // Benchmark Settings
  const [msgCount, setMsgCount] = useState(50);
  const [msgSize, setMsgSize] = useState("1KB");
  const [selectedSystems, setSelectedSystems] = useState(["DH_CBC_HMAC", "ECDH_CBC_HMAC", "ECDH_AEAD"]);

  const scrollRef = useRef(null);
  const terminalRef = useRef(null);


  useEffect(() => {
    initSession();
    fetchHistory();
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, eccMessages, aeadMessages]);

  const initSession = async () => {
    try {
      const res = await axios.post(`${API_BASE}/session/init`);
      setSessionId(res.data.session_id);
    } catch (err) {
      console.error("Session init failed", err);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await axios.get(`${API_BASE}/history`);
      setMessages(res.data.messages);
      setAeadMessages(res.data.aead_messages || []);
      
      const currentMsgs = systemMode === "CLASSIC" ? res.data.messages : 
                         (systemMode === "AEAD" ? res.data.aead_messages : eccMessages);
      if (currentMsgs && currentMsgs.length > 0) {
        setSelectedMsg(currentMsgs[currentMsgs.length - 1]);
      }
    } catch (err) {
      console.error("Fetch history failed", err);
    }
  };


  const sendMessage = async () => {
    if (!inputText.trim()) return;
    setLoading(true);
    try {
      let endpoint;
      if (systemMode === "CLASSIC") endpoint = "/message/send";
      else if (systemMode === "ECC_CBC") endpoint = "/message/send-ecc";
      else endpoint = "/message/send-aead";

      const res = await axios.post(`${API_BASE}${endpoint}`, {
        sender: activeSender,
        plaintext: inputText
      });

      if (systemMode === "CLASSIC") setMessages([...messages, res.data]);
      else if (systemMode === "ECC_CBC") setEccMessages([...eccMessages, res.data]);
      else setAeadMessages([...aeadMessages, res.data]);
      
      setSelectedMsg(res.data);
      setInputText("");
    } catch (err) {
      console.error("Send failed", err);
    } finally {
      setLoading(false);
    }
  };

  const startSimulation = async (type) => {
    try {
      setLoading(true);
      let endpoint;
      if (systemMode === "CLASSIC") {
        endpoint = type === 'TAMPER' ? '/attack/tamper' : '/attack/replay';
      } else if (systemMode === "AEAD") {
        endpoint = type === 'TAMPER' ? '/attack/tamper-aead' : '/attack/replay-aead';
      } else {
        endpoint = type === 'TAMPER' ? '/attack/tamper' : '/attack/replay';
      }
      
      const res = await axios.post(`${API_BASE}${endpoint}`);
      setSimData(res.data);
      setSimStep(0);
      setIsAutoPlaying(true);
      setIsSimulating(true);
    } catch (err) {
      console.error("Simulation failed", err);
    } finally {
      setLoading(false);
    }
  };

  const runBenchmark = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/benchmark/run`);
      setBenchmarkResults(res.data);
      setShowBenchmark(true);
    } catch (err) {
      console.error("Benchmark failed", err);
    } finally {
      setLoading(false);
    }
  };

  const runComprehensiveBenchmark = async () => {
    setLabLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/benchmark/run`, {
        message_count: msgCount,
        message_size: msgSize,
        systems: selectedSystems
      });
      setExperimentResults(res.data);
      setLabTab("PERFORMANCE");
    } catch (err) {
      console.error("Experiment failed", err);
      alert("Benchmarking failed. Check backend connection.");
    } finally {
      setLabLoading(false);
    }
  };

  const exportResults = (format) => {
    if (!experimentResults) return;
    const data = JSON.stringify(experimentResults, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `crypto_benchmark_${new Date().toISOString()}.json`;
    link.click();
  };

  const closeSimulation = () => {
    setIsSimulating(false);
    setSimData(null);
    setSimStep(0);
    setIsAutoPlaying(true);
    fetchHistory();
  };

  useEffect(() => {
    let timer;
    if (isSimulating && isAutoPlaying && simData && simData.steps) {
      if (simStep < simData.steps.length - 1) {
        timer = setTimeout(() => {
          setSimStep(prev => prev + 1);
        }, 1500);
      } else {
        setIsAutoPlaying(false);
      }
    }
    return () => clearTimeout(timer);
  }, [isSimulating, isAutoPlaying, simStep, simData]);

  const getActiveMessages = () => {
    if (systemMode === "CLASSIC") return messages || [];
    if (systemMode === "ECC_CBC") return eccMessages || [];
    return aeadMessages || [];
  };

  const resetState = async () => {
    try {
      await initSession();
      setMessages([]);
      setEccMessages([]);
      setAeadMessages([]);
      setSelectedMsg(null);
    } catch (err) {
      console.error("Reset failed", err);
    }
  };

  return (
    <div className="dashboard">
      {/* Simulation Overlay */}
      {isSimulating && simData && (
        <div className="simulation-overlay">
          <div className="sim-container">
            <div className="sim-header">
              <div className="sim-badge">LIVE ANALYSIS: {simData.type} ATTACK</div>
              <button className="close-sim" onClick={closeSimulation}>&times;</button>
            </div>
            <div className="sim-content">
              <div className="sim-visuals">
                <div className="progress-track">
                  {(simData.steps || []).map((step, idx) => (
                    <div key={idx} className={`prog-node ${idx === simStep ? 'active' : ''} ${idx < simStep ? 'complete' : ''} ${step.status}`}>
                      <div className="node-icon">{step.status === 'attacker' ? <Zap size={16} /> : <Shield size={16} />}</div>
                      <div className="node-label">{step.title}</div>
                      {idx < (simData.steps || []).length - 1 && <div className="node-connector"></div>}
                    </div>
                  ))}
                </div>
                <div className="current-step-display">
                  <div className={`step-card-premium ${simData.steps[simStep]?.status}`}>
                    <h3>{simData.steps[simStep]?.title}</h3>
                    <p>{simData.steps[simStep]?.description}</p>
                    {simData.steps[simStep]?.impact && <div className="impact-box"><strong>Impact:</strong> {simData.steps[simStep].impact}</div>}
                  </div>
                </div>
              </div>
              <div className="sim-terminal">
                <div className="terminal-header"><div className="ter-dots"><span></span><span></span><span></span></div><div>crypto_analyzer.log</div></div>
                <div className="terminal-body" ref={terminalRef}>
                  {(simData.steps || []).slice(0, simStep + 1).map((s, i) => (
                    <div key={i} className={`ter-line ${s.status}`}>[{new Date().toLocaleTimeString()}] {s.title}: {s.description}</div>
                  ))}
                  {simStep === (simData.steps || []).length - 1 && (
                    <div className={`final-verdict ${simData.blocked ? 'success' : 'failure'}`}>
                      {simData.blocked ? "SECURITY MITIGATION SUCCESSFUL" : "VULNERABILITY EXPLOITED"}
                    </div>
                  )}
                  {simStep === (simData.steps || []).length - 1 && (
                    <button className="finish-sim-btn" onClick={closeSimulation} style={{marginTop: '1rem'}}>CLOSE ANALYSIS</button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {showAnalysis && (
        <div className="lab-overlay">
          <div className="lab-window">
            <div className="lab-header">
              <div className="lab-title-area">
                <Beaker size={24} className="lab-icon" />
                <div>
                  <div style={{fontWeight: 800, fontSize: '1.2rem'}}>CRYPTOGRAPHIC COMPARISON LAB</div>
                  <div className="lab-subtitle">Advanced Real-Time Benchmark & Security Scorecard</div>
                </div>
              </div>
              <button className="close-sim" onClick={() => setShowAnalysis(false)}>&times;</button>
            </div>

            <div className="lab-body">
              <aside className="lab-controls">
                <div className="control-group">
                  <div className="control-label">Protocol Selection</div>
                  <div className="system-check-list">
                    {[
                      {id: "DH_CBC_HMAC", label: "System A: Baseline DH-CBC"},
                      {id: "ECDH_CBC_HMAC", label: "System B: Optimized ECDH-CBC"},
                      {id: "ECDH_AEAD", label: "System C: Modern AEAD (GCM)"}
                    ].map(sys => (
                      <label key={sys.id} className="check-item">
                        <input 
                          type="checkbox" 
                          checked={selectedSystems.includes(sys.id)}
                          onChange={(e) => {
                            if (e.target.checked) setSelectedSystems([...selectedSystems, sys.id]);
                            else setSelectedSystems(selectedSystems.filter(s => s !== sys.id));
                          }}
                        />
                        {sys.label}
                      </label>
                    ))}
                  </div>
                </div>

                <div className="control-group">
                  <div className="control-label">Batch Message Count</div>
                  <div className="selector-grid">
                    {[10, 50, 100].map(c => (
                      <button 
                        key={c} 
                        className={`selector-btn ${msgCount === c ? 'active' : ''}`}
                        onClick={() => setMsgCount(c)}
                      >
                        {c} Msgs
                      </button>
                    ))}
                  </div>
                </div>

                <div className="control-group">
                  <div className="control-label">Payload Size</div>
                  <div className="selector-grid">
                    {["64B", "1KB", "10KB", "100KB"].map(s => (
                      <button 
                        key={s} 
                        className={`selector-btn ${msgSize === s ? 'active' : ''}`}
                        onClick={() => setMsgSize(s)}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>

                <button 
                  className="run-bench-btn" 
                  onClick={runComprehensiveBenchmark}
                  disabled={labLoading || selectedSystems.length === 0}
                >
                  {labLoading ? <RefreshCw size={20} className="spin" /> : <Zap size={20} />}
                  RUN COMPARISON
                </button>
              </aside>

              <main className="lab-results">
                {labLoading ? (
                  <div className="loading-lab">
                    <RefreshCw size={64} className="spin muted" />
                    <div style={{textAlign: 'center'}}>
                      <h2 style={{color: '#1e293b'}}>Benchmarking Systems...</h2>
                      <p>Processing {msgCount} messages through active pipelines</p>
                    </div>
                    <div className="progress-bar-lab"><div className="progress-fill-lab"></div></div>
                  </div>
                ) : experimentResults ? (
                  <div className="results-wrapper animate-fade-in">
                    {/* Navigation Tabs */}
                    <div className="lab-tabs-premium">
                      {["DASHBOARD", "PERFORMANCE", "SECURITY", "STATISTICAL"].map(tab => (
                        <div 
                          key={tab} 
                          className={`lab-tab-p ${labTab === tab ? 'active' : ''}`}
                          onClick={() => setLabTab(tab)}
                        >
                          {tab}
                        </div>
                      ))}
                    </div>

                    {labTab === "DASHBOARD" && (
                      <div className="lab-tab-content">
                        <div className="section-title-premium"><Table size={20} /> Comparative Performance Summary</div>
                        <div className="results-grid">
                          {experimentResults.results.map((res, i) => (
                            <div key={i} className="system-res-card">
                              <div className="res-card-header">
                                <div className="res-card-title">
                                  <h3>{res.system_name.replace(/_/g, ' ')}</h3>
                                  <p>{res.message_count} msgs @ {res.message_size}</p>
                                </div>
                                {experimentResults.summary.best_encryption_speed === res.system_name && <div className="badge-winner">Fastest</div>}
                                {experimentResults.summary.lowest_packet_overhead === res.system_name && <div className="badge-winner" style={{background: '#eff6ff', color: '#2563eb'}}>Leanest</div>}
                              </div>
                              
                              <div className="metric-strip">
                                <div className="metric-mini">
                                  <div className="m-label">Avg. Latency</div>
                                  <div className="m-value">{res.total_round_trip_time_ms_avg.toFixed(3)} ms</div>
                                </div>
                                <div className="metric-mini">
                                  <div className="m-label">Throughput</div>
                                  <div className="m-value">{Math.round(res.throughput_messages_per_second)} msg/s</div>
                                </div>
                              </div>

                              <div className="metric-mini" style={{marginBottom: '1rem'}}>
                                <div className="m-label">Tamper Detection Rate</div>
                                <div className="m-value" style={{color: '#10b981'}}>{res.tamper_detection_success_rate_percent}%</div>
                              </div>

                              <div className="bar-track-custom">
                                <div 
                                  className={`bar-fill-custom ${res.system_name.includes('AEAD') ? 'aead' : (res.system_name.includes('ECDH') ? 'ecdh' : 'dh')}`}
                                  style={{width: `${Math.max(20, 100 - (res.total_round_trip_time_ms_avg * 10))}%`}}
                                ></div>
                              </div>
                            </div>
                          ))}
                        </div>

                        <div className="recommendation-panel">
                          <div className="rec-icon"><ShieldCheck size={32} /></div>
                          <div className="rec-content">
                            <h2>Research Verdict: {experimentResults.summary.recommended_final_system}</h2>
                            <p>
                              Based on real-time analysis of {msgCount} transmissions, System C (AEAD) demonstrates superior efficiency. 
                              It reduces <strong>bandwidth overhead</strong> by ~{Math.round(100 - (experimentResults.results.find(r => r.system_name === 'ECDH_AEAD')?.avg_packet_size_bytes / experimentResults.results[0]?.avg_packet_size_bytes * 100))}% 
                              compared to Legacy DH, while maintaining strong security through integrated authentication.
                            </p>
                            <div className="rec-stats">
                              <div className="stat-item-premium">
                                <div className="s-label">Winner: Speed</div>
                                <div className="s-val">{experimentResults.summary.best_encryption_speed.replace(/_/g, ' ')}</div>
                              </div>
                              <div className="stat-item-premium">
                                <div className="s-label">Winner: Bandwidth</div>
                                <div className="s-val">{experimentResults.summary.lowest_packet_overhead.replace(/_/g, ' ')}</div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {labTab === "PERFORMANCE" && (
                      <div className="lab-tab-content">
                        <div className="chart-row-premium">
                          <div className="chart-card-custom">
                            <div className="chart-header-custom">Latency Comparison (ms) - Lower is Better</div>
                            <div className="bar-container-custom">
                              {experimentResults.results.map((res, i) => (
                                <div key={i} className="bar-item-custom">
                                  <div className="bar-label-custom">
                                    <span>{res.system_name}</span>
                                    <span>{res.total_round_trip_time_ms_avg.toFixed(3)} ms</span>
                                  </div>
                                  <div className="bar-track-custom">
                                    <div 
                                      className={`bar-fill-custom ${res.system_name.includes('AEAD') ? 'aead' : (res.system_name.includes('ECDH') ? 'ecdh' : 'dh')}`}
                                      style={{width: `${(res.total_round_trip_time_ms_avg / Math.max(...experimentResults.results.map(r => r.total_round_trip_time_ms_avg))) * 100}%`}}
                                    ></div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>

                          <div className="chart-card-custom">
                            <div className="chart-header-custom">Handshake Speed (ms) - Key Exchange</div>
                            <div className="bar-container-custom">
                              {experimentResults.results.map((res, i) => (
                                <div key={i} className="bar-item-custom">
                                  <div className="bar-label-custom">
                                    <span>{res.system_name}</span>
                                    <span>{res.key_generation_time_ms.toFixed(3)} ms</span>
                                  </div>
                                  <div className="bar-track-custom">
                                    <div 
                                      className={`bar-fill-custom ${res.system_name.includes('AEAD') ? 'aead' : (res.system_name.includes('ECDH') ? 'ecdh' : 'dh')}`}
                                      style={{width: `${(res.key_generation_time_ms / Math.max(...experimentResults.results.map(r => r.key_generation_time_ms))) * 100}%`}}
                                    ></div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div className="section-title-premium"><Activity size={20} /> Deep Resource Metrics</div>
                        <table className="full-metrics-table">
                          <thead>
                            <tr>
                              <th>Metric Parameter</th>
                              {experimentResults.results.map(r => <th key={r.system_name}>{r.system_name}</th>)}
                            </tr>
                          </thead>
                          <tbody>
                            <tr>
                              <td className="row-label">Avg. Packet Size (Bytes)</td>
                              {experimentResults.results.map(r => <td>{Math.round(r.avg_packet_size_bytes)} B</td>)}
                            </tr>
                            <tr>
                              <td className="row-label">Encryption Latency</td>
                              {experimentResults.results.map(r => <td>{r.encryption_time_ms_avg.toFixed(4)} ms</td>)}
                            </tr>
                            <tr>
                              <td className="row-label">Transformation Overhead</td>
                              {experimentResults.results.map(r => <td>{r.transformation_time_ms_avg.toFixed(4)} ms</td>)}
                            </tr>
                            <tr>
                              <td className="row-label">Bandwidth Expansion</td>
                              {experimentResults.results.map(r => <td>{r.bandwidth_overhead_percent.toFixed(2)} %</td>)}
                            </tr>
                            <tr>
                              <td className="row-label">Throughput (Batch)</td>
                              {experimentResults.results.map(r => <td>{Math.round(r.throughput_messages_per_second)} msg/s</td>)}
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    )}

                    {labTab === "SECURITY" && (
                      <div className="lab-tab-content">
                        <div className="section-title-premium"><Shield size={20} /> Integrity & Attack Resistance Matrix</div>
                        <table className="full-metrics-table">
                          <thead>
                            <tr>
                              <th>Security Parameter</th>
                              {experimentResults.results.map(r => <th key={r.system_name}>{r.system_name}</th>)}
                            </tr>
                          </thead>
                          <tbody>
                            <tr>
                              <td className="row-label">Tamper Detection (Bit-Flip)</td>
                              {experimentResults.results.map(r => <td className="best-val">{r.tamper_detection_success_rate_percent}%</td>)}
                            </tr>
                            <tr>
                              <td className="row-label">Replay Attack Prevention</td>
                              {experimentResults.results.map(r => <td className="best-val">{r.replay_detection_success_rate_percent}%</td>)}
                            </tr>
                            <tr>
                              <td className="row-label">Decryption Success Rate</td>
                              {experimentResults.results.map(r => <td>{r.successful_decryption_rate_percent}%</td>)}
                            </tr>
                            <tr>
                              <td className="row-label">Forward Secrecy</td>
                              {experimentResults.results.map(r => <td>{r.feature_flags.forward_secrecy ? 'ENABLED' : 'DISABLED'}</td>)}
                            </tr>
                            <tr>
                              <td className="row-label">Context-Bound Keys</td>
                              {experimentResults.results.map(r => <td>{r.feature_flags.context_binding ? 'ACTIVE' : 'INACTIVE'}</td>)}
                            </tr>
                            <tr>
                              <td className="row-label">Transformation Proof</td>
                              {experimentResults.results.map(r => <td>{r.feature_flags.transform_proof ? 'VERIFIED' : 'N/A'}</td>)}
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    )}

                    {labTab === "STATISTICAL" && (
                      <div className="lab-tab-content">
                         <div className="section-title-premium"><PieChart size={20} /> Cryptographic Quality Metrics</div>
                         <div className="chart-row-premium">
                           <div className="chart-card-custom">
                             <div className="chart-header-custom">Ciphertext Entropy (Bits per Byte) - High is Better</div>
                             <div className="bar-container-custom">
                               {experimentResults.results.map((res, i) => (
                                 <div key={i} className="bar-item-custom">
                                   <div className="bar-label-custom">
                                     <span>{res.system_name}</span>
                                     <span>{res.ciphertext_entropy_avg.toFixed(4)}</span>
                                   </div>
                                   <div className="bar-track-custom">
                                     <div 
                                       className="bar-fill-custom"
                                       style={{background: '#8b5cf6', width: `${(res.ciphertext_entropy_avg / 8) * 100}%`}}
                                     ></div>
                                   </div>
                                 </div>
                               ))}
                             </div>
                           </div>
                           <div className="chart-card-custom">
                             <div className="chart-header-custom">Unique Output Rate (Non-Deterministic Check)</div>
                             <div className="bar-container-custom">
                               {experimentResults.results.map((res, i) => (
                                 <div key={i} className="bar-item-custom">
                                   <div className="bar-label-custom">
                                     <span>{res.system_name}</span>
                                     <span>{res.unique_output_rate_percent}%</span>
                                   </div>
                                   <div className="bar-track-custom">
                                     <div 
                                       className="bar-fill-custom"
                                       style={{background: '#f59e0b', width: `${res.unique_output_rate_percent}%`}}
                                     ></div>
                                   </div>
                                 </div>
                               ))}
                             </div>
                           </div>
                         </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="empty-lab">
                    <Database size={64} className="muted" />
                    <h2>No Experimental Data Found</h2>
                    <p>Select your parameters and click "Run Comparison" to start the analysis.</p>
                  </div>
                )}
              </main>
            </div>

            <div className="lab-footer">
              <div style={{marginRight: 'auto', display: 'flex', gap: '1rem'}}>
                 <button className="export-btn" onClick={() => exportResults('json')} disabled={!experimentResults}>
                   <FileText size={16} /> Export JSON
                 </button>
              </div>
              <button className="selector-btn" onClick={() => setShowAnalysis(false)}>Close Lab</button>
            </div>
          </div>
        </div>
      )}

      {/* Benchmark Modal */}
      {showBenchmark && benchmarkResults && (
        <div className="simulation-overlay">
          <div className="sim-container benchmark-container">
            <div className="sim-header">
              <div className="sim-badge">PERFORMANCE BENCHMARK (3-WAY)</div>
              <button className="close-sim" onClick={() => setShowBenchmark(false)}>&times;</button>
            </div>
            <div className="benchmark-content">
              {(benchmarkResults || []).map((res, i) => (
                <div key={i} className="benchmark-card-3">
                  <div className="metric-header">{res.metric}</div>
                  <div className="comparison-bars">
                    <div className="comp-item">
                      <div className="comp-label">Legacy DH</div>
                      <div className="comp-bar-bg"><div className="comp-bar classic" style={{width: '100%'}}></div></div>
                      <div className="comp-val">{(res.classic_value || 0).toFixed(3)} {res.unit}</div>
                    </div>
                    <div className="comp-item">
                      <div className="comp-label">Hybrid ECC</div>
                      <div className="comp-bar-bg"><div className="comp-bar ecc" style={{width: `${(res.ecc_value / (res.classic_value || 1)) * 100}%`}}></div></div>
                      <div className="comp-val">{(res.ecc_value || 0).toFixed(3)} {res.unit}</div>
                    </div>
                    <div className="comp-item">
                      <div className="comp-label">Modern AEAD</div>
                      <div className="comp-bar-bg"><div className="comp-bar aead" style={{width: `${(res.aead_value / (res.classic_value || 1)) * 100}%`}}></div></div>
                      <div className="comp-val">{(res.aead_value || 0).toFixed(3)} {res.unit}</div>
                    </div>
                  </div>
                </div>
              ))}
              <div className="bench-footer">
                <p><Info size={14} /> AEAD combines encryption and integrity, reducing round-trip overhead.</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="logo"><ShieldCheck size={24} /> <span>SecureChat Lab</span></div>
        </div>
        <div className="search-container"><div className="search-box"><Search size={16} /> <span>Search secure sessions...</span></div></div>
        
        <div className="channel-list">
          <div className="channel-section-title">Verified Channels</div>
          
          <div className={`channel-item ${activeSender === 'ALICE' ? 'active' : ''}`} onClick={() => setActiveSender('ALICE')}>
            <div className="avatar">
              <img src="https://ui-avatars.com/api/?name=Alice+Mitchell&background=6366f1&color=fff" alt="Alice" />
            </div>
            <div className="channel-info">
              <div className="channel-name">Alice Mitchell</div>
              <div className="channel-status">Handshake: {systemMode}</div>
            </div>
            <Shield size={14} color="var(--success)" />
          </div>

          <div className={`channel-item ${activeSender === 'BOB' ? 'active' : ''}`} onClick={() => setActiveSender('BOB')}>
            <div className="avatar">
              <img src="https://ui-avatars.com/api/?name=Bob+Henderson&background=4f46e5&color=fff" alt="Bob" />
            </div>
            <div className="channel-info">
              <div className="channel-name">Bob Henderson</div>
              <div className="channel-status">Status: Encrypted</div>
            </div>
            <Shield size={14} color="var(--success)" />
          </div>

          <div className="channel-item">
            <div className="avatar">
              <img src="https://ui-avatars.com/api/?name=Charlie+Root&background=94a3b8&color=fff" alt="Charlie" />
            </div>
            <div className="channel-info">
              <div className="channel-name">Charlie Root</div>
              <div className="channel-status">Last seen: 2m ago</div>
            </div>
          </div>
        </div>

        <div className="sidebar-footer">
          <button className="sim-btn premium-btn" onClick={() => { setShowAnalysis(true); setLabTab('OVERVIEW'); }}>
            <Beaker size={14} /> COMPARISON LAB
          </button>
          <button className="sim-btn secondary-btn" onClick={runBenchmark}>
            <BarChart3 size={14} /> PERFORMANCE
          </button>
        </div>
      </aside>

      {/* Main Chat */}
      <main className="main-chat">
        <header className="chat-header">
          <div className="chat-user-info">
            <div className="status-indicator online"></div>
            <div>
              <div className="chat-user-name">{activeSender === 'ALICE' ? 'Alice Mitchell' : 'Bob Henderson'}</div>
              <div className="chat-user-status">SECURE SESSION ACTIVE ({systemMode.replace('_', ' ')})</div>
            </div>
          </div>
          <div className="header-actions">
            <div className="mode-switcher">
              <Layers size={14} />
              <select value={systemMode} onChange={(e) => setSystemMode(e.target.value)}>
                <option value="CLASSIC">SYSTEM A: DH + CBC + HMAC</option>
                <option value="ECC_CBC">SYSTEM B: ECDH + CBC + HMAC</option>
                <option value="AEAD">SYSTEM C: ECDH + AEAD-GCM</option>
              </select>
            </div>
          </div>
        </header>

        <section className="chat-messages" ref={scrollRef}>
          {getActiveMessages().map((m, i) => (
            <div key={i} className={`message-wrapper ${m.sender?.toLowerCase() || 'system'}`}>
              <div className={`message-card ${selectedMsg?.id === m.id ? 'selected' : ''}`} onClick={() => setSelectedMsg(m)}>
                <div className="message-text">{m.decrypted_plaintext || m.plaintext}</div>
                <div className="message-footer">
                  <span>IDX: #{m.index}</span>
                  <span>{new Date((m.timestamp || 0) * 1000).toLocaleTimeString()}</span>
                </div>
              </div>
            </div>
          ))}
        </section>

        <section className="chat-input-area">
          <div className="input-container">
            <div className="sender-toggle" onClick={() => setActiveSender(prev => prev === "ALICE" ? "BOB" : "ALICE")}>{activeSender}</div>
            <input placeholder="Enter secret transmission..." value={inputText} onChange={(e) => setInputText(e.target.value)} onKeyPress={(e) => e.key === 'Enter' && sendMessage()} />
            <button className="send-btn" onClick={sendMessage} disabled={loading}><Send size={18} /></button>
          </div>
        </section>
      </main>

      {/* Security Panel */}
      <aside className="security-panel">
        <div className="pipeline-header"><Shield size={18} /> <span>SECURITY INTERNALS</span></div>
        <div className="pipeline-content">
          {selectedMsg ? (
            <div className="security-scroll">
              <div className="pipeline-card active">
                <div className="card-header"><div className="card-title"><Key size={14} /> KEY SCHEDULE</div><div className="v-badge">ACTIVE</div></div>
                <div className="card-body">Derived via {systemMode.includes('ECC') ? 'ECDH' : 'Classic DH'}.<br/>Root Key: {selectedMsg.key_preview}</div>
              </div>
              <div className="pipeline-card active">
                <div className="card-header"><div className="card-title"><Zap size={14} /> POLYMORPHIC LAYER</div></div>
                <div className="card-body">State-dependent mutation active.<br/><div className="code-snippet">{(selectedMsg.transformed_ciphertext || selectedMsg.transformed_ciphertext_hex || "").slice(0, 32)}...</div></div>
              </div>
              <div className="pipeline-card">
                <div className="card-header"><div className="card-title"><Layers size={14} /> WIRE PACKET</div></div>
                <div className="card-body">Size: {selectedMsg.packet_length} Bytes<br/>Nonce/IV: {(selectedMsg.nonce || selectedMsg.iv || "").slice(0, 16)}</div>
              </div>
              <div className="pipeline-card active">
                <div className="card-header"><div className="card-title"><Shield size={14} /> INTEGRITY</div><div className="v-badge">VALID</div></div>
                <div className="card-body">
                  Method: {systemMode === 'AEAD' ? 'GCM Auth Tag' : 'HMAC-SHA256'}<br/>
                  <div className={`status-pill ${selectedMsg.integrity_ok || selectedMsg.aead_verified ? 'success' : 'error'}`}>
                    {selectedMsg.integrity_ok || selectedMsg.aead_verified ? 'VERIFIED' : 'FAILED'}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="empty-security"><Lock size={48} /><p>Select message for analysis</p></div>
          )}
        </div>
        <div className="sim-actions">
          <button className="sim-btn" onClick={() => startSimulation('REPLAY')}>TEST REPLAY</button>
          <button className="sim-btn danger" onClick={() => startSimulation('TAMPER')}>TEST TAMPER</button>
          <button className="sim-btn reset" style={{gridColumn: 'span 2'}} onClick={resetState}>RESET SESSION</button>
        </div>
      </aside>
    </div>
  );
};

export default App;
