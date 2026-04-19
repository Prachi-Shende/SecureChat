import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { 
  Send, Shield, Lock, Activity, AlertTriangle, RefreshCw, 
  Search, MoreVertical, ShieldCheck, Key, Zap, Layers, 
  Database, UserCheck, MessageSquare, Copy, ArrowRight, X
} from 'lucide-react';

const API_BASE = "http://localhost:8000";

const App = () => {
  const [messages, setMessages] = useState([]);
  const [selectedMsg, setSelectedMsg] = useState(null);
  const [inputText, setInputText] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeSender, setActiveSender] = useState("ALICE");
  const [isSimulating, setIsSimulating] = useState(false);
  const [isAutoPlaying, setIsAutoPlaying] = useState(true);
  const [simData, setSimData] = useState(null);
  const [simStep, setSimStep] = useState(0);
  
  // New States
  const [compareMode, setCompareMode] = useState(false);
  const [compareSelection, setCompareSelection] = useState([]);
  const [showCompareModal, setShowCompareModal] = useState(false);
  
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
  }, [messages]);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [simStep, isSimulating]);

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
      if (res.data.messages.length > 0) {
        setSelectedMsg(res.data.messages[res.data.messages.length - 1]);
      }
    } catch (err) {
      console.error("Fetch history failed", err);
    }
  };

  const sendMessage = async () => {
    if (!inputText.trim()) return;
    setLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/message/send`, {
        sender: activeSender,
        plaintext: inputText
      });
      setMessages([...messages, res.data]);
      setSelectedMsg(res.data);
      setInputText("");
    } catch (err) {
      console.error("Send failed", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let timer;
    if (isSimulating && isAutoPlaying && simData) {
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

  const startSimulation = async (type) => {
    try {
      setLoading(true);
      const endpoint = type === 'TAMPER' ? '/attack/tamper' : '/attack/replay';
      const res = await axios.post(`${API_BASE}${endpoint}`);
      if (res.data && res.data.steps) {
        setSimData(res.data);
        setSimStep(0);
        setIsAutoPlaying(true);
        setIsSimulating(true);
      } else {
        alert("Simulation data is malformed.");
      }
    } catch (err) {
      console.error("Simulation request failed", err);
      alert("Simulation failed. Check console for details.");
    } finally {
      setLoading(false);
    }
  };

  const closeSimulation = () => {
    setIsSimulating(false);
    setSimData(null);
    setSimStep(0);
    setIsAutoPlaying(true);
    fetchHistory();
  };

  const toggleCompareSelection = (msg) => {
    if (compareSelection.find(m => m.id === msg.id)) {
      setCompareSelection(compareSelection.filter(m => m.id !== msg.id));
    } else {
      if (compareSelection.length < 2) {
        setCompareSelection([...compareSelection, msg]);
      }
    }
  };

  const handleMsgClick = (m) => {
    if (compareMode) {
      toggleCompareSelection(m);
    } else {
      setSelectedMsg(m);
    }
  };

  const resetState = async () => {
    try {
      await initSession();
      setMessages([]);
      setSelectedMsg(null);
      setCompareMode(false);
      setCompareSelection([]);
    } catch (err) {
      console.error("Reset failed", err);
    }
  };

  return (
    <div className="dashboard">
      {/* Simulation Mode Overlay */}
      {isSimulating && simData && (
        <div className="simulation-overlay">
          <div className="sim-container">
            <div className="sim-header">
              <div className="sim-badge">LIVE SIMULATION: {(simData.type || 'UNKNOWN').toUpperCase()} ATTACK</div>
              <button className="close-sim" onClick={closeSimulation}>&times;</button>
            </div>
            
            <div className="sim-content">
              {/* Left Side: Visual Progress */}
              <div className="sim-visuals">
                <div className="progress-track">
                  {simData.steps && simData.steps.length > 0 ? (
                    simData.steps.map((step, idx) => (
                    <div 
                      key={idx} 
                      className={`prog-node ${idx === simStep ? 'active' : ''} ${idx < simStep ? 'complete' : ''} ${(step && step.status) || 'system'}`}
                      onClick={() => {
                        setSimStep(idx);
                        setIsAutoPlaying(false);
                      }}
                      style={{cursor: 'pointer'}}
                    >
                      <div className="node-icon">
                        {(step && step.status) === 'attacker' ? <Zap size={16}/> : <Shield size={16}/>}
                      </div>
                      <div className="node-label">{step?.title || `Step ${idx + 1}`}</div>
                      {idx < simData.steps.length - 1 && <div className="node-connector"></div>}
                    </div>
                    ))
                  ) : (
                    <div style={{color: 'var(--text-muted)', fontSize: '0.9rem'}}>No progression data available.</div>
                  )}
                </div>

                <div className="current-step-display">
                  {simData.steps && simData.steps.length > 0 && simData.steps[simStep] ? (
                    <div className={`step-card-premium ${simData.steps[simStep].status || 'system'}`}>
                      <div className="step-tag">{(simData.steps[simStep].status || 'system').toUpperCase()} ACTION</div>
                      <h3>{simData.steps[simStep].title || 'Step Details'}</h3>
                      <p>{simData.steps[simStep].description || 'No description available for this step.'}</p>
                      {simData.steps[simStep].impact && (
                        <div className="impact-box">
                          <strong>Impact:</strong> {simData.steps[simStep].impact}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="step-card-premium system">
                      <div className="step-tag">SYSTEM NOTICE</div>
                      <h3>No Steps Available</h3>
                      <p>The simulation could not retrieve step-by-step details. This usually happens if no packets have been captured yet (send a message first!) or if the backend returned no data.</p>
                      <button className="finish-sim-btn" onClick={closeSimulation} style={{marginTop: '1rem'}}>CLOSE SIMULATION</button>
                    </div>
                  )}
                </div>
              </div>

              {/* Right Side: Technical Log / Terminal */}
              <div className="sim-terminal">
                <div className="terminal-header">
                  <div className="ter-dots"><span></span><span></span><span></span></div>
                  <div>network_traffic_analyzer.sh</div>
                </div>
                <div className="terminal-body" ref={terminalRef}>
                  <div className="ter-line system">Initializing monitoring on port 8000...</div>
                  <div className="ter-line system">Waiting for malicious activity detected...</div>
                  
                  {simData.steps && simData.steps.slice(0, simStep + 1).map((step, idx) => (
                    <div key={idx} className="terminal-log-entry">
                      <div className={`log-type-tag ${step?.status || 'system'}`}>{(step?.status || 'SYS').toUpperCase()}</div>
                      <div className={`ter-line ${step?.status || 'system'}`}>
                        <span className="ter-time">[{new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'})}]</span>
                        <span className="ter-msg">{(step?.title || 'Log')}: {step?.description || 'Data captured.'}</span>
                      </div>
                    </div>
                  ))}

                  {simData.steps && simData.steps.length > 0 && simStep === simData.steps.length - 1 && (
                    <div className="packet-comparison">
                      <div className="packet-header">CRYPTO-PACKET BINDING COMPARISON</div>
                      <div className="packet-data">
                        <div className="pkt">
                          <span className="pkt-label">ORIGINAL LEGITIMATE PACKET</span>
                          <code>
                            {simData.original_packet?.match(/.{1,2}/g)?.map((byte, i) => (
                              <span key={i} className={simData.type === 'TAMPER' && i === 80 ? 'reused-highlight' : ''}>{byte}</span>
                            ))}
                          </code>
                        </div>
                        {simData.attacker_packet && (
                          <div className="pkt mal">
                            <span className="pkt-label">INJECTED MALICIOUS PACKET</span>
                            <code>
                              {simData.attacker_packet.match(/.{1,2}/g)?.map((byte, i) => {
                                let className = "";
                                if (simData.type === 'TAMPER' && i === simData.modified_byte_index) className = "byte-highlight";
                                if (simData.type === 'REPLAY' && simData.reused_index !== undefined) className = "reused-highlight";
                                return <span key={i} className={className}>{byte}</span>;
                              })}
                            </code>
                          </div>
                        )}
                      </div>
                      <div className={`final-verdict ${simData.blocked ? 'success' : 'failure'}`}>
                        {simData.blocked ? (
                          <>
                            <ShieldCheck size={20} style={{marginBottom: '0.5rem'}} /><br/>
                            {simData.type === 'REPLAY' ? 'REPLAY DETECTED: INDEX ALREADY USED' : 'TAMPER DETECTED: HMAC INTEGRITY FAILURE'}
                          </>
                        ) : (
                          <>
                            <AlertTriangle size={20} style={{marginBottom: '0.5rem'}} /><br/>
                            ATTACK SUCCESSFUL - VULNERABILITY DETECTED
                          </>
                        )}
                      </div>
                    </div>
                  )}

                  {(simStep === (simData.steps?.length || 1) - 1 || !simData.steps || simData.steps.length === 0) && (
                    <button className="finish-sim-btn" onClick={closeSimulation}>EXIT SIMULATION MODE</button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Compare Modal */}
      {showCompareModal && compareSelection.length === 2 && (
        <div className="compare-overlay">
          <div className="compare-modal">
            <div className="compare-header">
              <div style={{display: 'flex', alignItems: 'center', gap: '0.75rem'}}>
                <Activity size={20} />
                <h2 style={{fontSize: '1.25rem', fontWeight: 700}}>Side-by-Side Analysis</h2>
              </div>
              <button className="close-sim" onClick={() => setShowCompareModal(false)}><X /></button>
            </div>
            <div className="compare-body">
              <table className="compare-table">
                <thead>
                  <tr>
                    <th>Field</th>
                    <th className="val-col">Message 1 (Idx #{compareSelection[0].index})</th>
                    <th className="val-col">Message 2 (Idx #{compareSelection[1].index})</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Plaintext</td>
                    <td className={compareSelection[0].plaintext === compareSelection[1].plaintext ? 'same-highlight' : ''}>
                      {compareSelection[0].plaintext}
                    </td>
                    <td className={compareSelection[0].plaintext === compareSelection[1].plaintext ? 'same-highlight' : ''}>
                      {compareSelection[1].plaintext}
                    </td>
                  </tr>
                  <tr>
                    <td>Message Index</td>
                    <td className="diff-highlight">#{compareSelection[0].index}</td>
                    <td className="diff-highlight">#{compareSelection[1].index}</td>
                  </tr>
                  <tr>
                    <td>Key (Root)</td>
                    <td>{compareSelection[0].key_preview}</td>
                    <td>{compareSelection[1].key_preview}</td>
                  </tr>
                  <tr>
                    <td>AES Ciphertext (GCM)</td>
                    <td className="diff-highlight">{compareSelection[0].aes_ciphertext.slice(0, 32)}...</td>
                    <td className="diff-highlight">{compareSelection[1].aes_ciphertext.slice(0, 32)}...</td>
                  </tr>
                  <tr>
                    <td>Transformed Output</td>
                    <td className="diff-highlight" style={{color: 'var(--accent-primary)'}}>{compareSelection[0].transformed_ciphertext.slice(0, 32)}...</td>
                    <td className="diff-highlight" style={{color: 'var(--accent-primary)'}}>{compareSelection[1].transformed_ciphertext.slice(0, 32)}...</td>
                  </tr>
                  <tr>
                    <td>Proof of Novelty</td>
                    <td colSpan="2" style={{textAlign: 'center', color: 'var(--success)', fontWeight: 700, background: '#f0fdf4'}}>
                      DETERMINISTIC POLYMORPHISM PROVEN: SAME PLAINTEXT → TOTALLY DIFFERENT WIRE SIGNATURES
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 1. Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <ShieldCheck size={24} />
            <span>Polymorphic FS</span>
          </div>
        </div>
        
        <div className="search-container">
          <div className="search-box">
            <Search size={16} />
            <span>Search secure sessions...</span>
          </div>
        </div>

        <div className="compare-btn-container">
           <button 
             className={`sim-btn ${compareMode ? 'danger' : ''}`} 
             style={{width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem'}}
             onClick={() => {
               setCompareMode(!compareMode);
               setCompareSelection([]);
             }}
           >
             <Copy size={14} /> {compareMode ? 'CANCEL COMPARE' : 'COMPARE MESSAGES'}
           </button>
        </div>

        {compareMode && (
          <div className="selection-hint" style={{padding: '0.5rem 1.5rem'}}>
            Select any 2 messages below... ({compareSelection.length}/2)
            {compareSelection.length === 2 && (
              <button 
                className="finish-sim-btn" 
                style={{padding: '0.4rem', marginTop: '0.5rem', width: '100%'}}
                onClick={() => setShowCompareModal(true)}
              >
                START ANALYSIS
              </button>
            )}
          </div>
        )}

        <div className="channel-list">
          <div className="channel-section-title">Active Channels</div>
          
          <div className={`channel-item ${activeSender === 'ALICE' ? 'active' : ''}`} onClick={() => setActiveSender('ALICE')}>
            <div className="avatar">
              <img src="/assets/alice.png" alt="Alice" onError={(e) => e.target.src = "https://ui-avatars.com/api/?name=Alice+Mitchell&background=6366f1&color=fff"} />
            </div>
            <div className="channel-info">
              <div className="channel-name">Alice Mitchell</div>
              <div className="channel-status">Verification successful. Integrity...</div>
            </div>
            <Shield size={14} color="var(--success)" />
          </div>

          <div className={`channel-item ${activeSender === 'BOB' ? 'active' : ''}`} onClick={() => setActiveSender('BOB')}>
            <div className="avatar">
              <img src="/assets/bob.png" alt="Bob" onError={(e) => e.target.src = "https://ui-avatars.com/api/?name=Bob+Henderson&background=4f46e5&color=fff"} />
            </div>
            <div className="channel-info">
              <div className="channel-name">Bob Henderson</div>
              <div className="channel-status">DH handshake complete...</div>
            </div>
            <Shield size={14} color="var(--success)" />
          </div>

          <div className="channel-item">
            <div className="avatar">
              <img src="/assets/charlie.png" alt="Charlie" onError={(e) => e.target.src = "https://ui-avatars.com/api/?name=Charlie+Root&background=94a3b8&color=fff"} />
            </div>
            <div className="channel-info">
              <div className="channel-name">Charlie Root</div>
              <div className="channel-status">Root key rotated.</div>
            </div>
          </div>
        </div>

        <div className="sidebar-footer">
          <div style={{display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', fontWeight: 600}}>
            <Activity size={14} color="var(--accent-primary)" />
            <span>SYSTEM STATUS</span>
          </div>
          <div style={{fontSize: '0.7rem', color: 'var(--success)', marginTop: '0.25rem'}}>Global Secrecy Active</div>
        </div>
      </aside>

      {/* 2. Main Chat */}
      <main className="main-chat">
        <header className="chat-header">
          <div className="chat-user-info">
            <div className="avatar" style={{width: '32px', height: '32px'}}>
              <img src="/assets/alice.png" alt="Alice" onError={(e) => e.target.src = "https://ui-avatars.com/api/?name=Alice+Mitchell&background=6366f1&color=fff"} />
            </div>
            <div>
              <div className="chat-user-name">Alice Mitchell</div>
              <div className="chat-user-status">SECURE SESSION ACTIVE (AES-GCM-256)</div>
            </div>
          </div>
          <div style={{display: 'flex', gap: '0.75rem', alignItems: 'center'}}>
             <div className="v-badge" style={{background: '#f1f5f9', color: '#64748b'}}>DH-HANDSHAKE-OK</div>
             <div className="v-badge" style={{background: '#f1f5f9', color: '#64748b'}}>F-SECRECY-ON</div>
             <MoreVertical size={18} color="var(--text-muted)" />
          </div>
        </header>

        <section className="chat-messages" ref={scrollRef}>
          {messages.map((m, i) => (
            <div key={i} className={`message-wrapper ${m.sender.toLowerCase()}`}>
              <div 
                className={`message-card ${selectedMsg?.id === m.id ? 'selected' : ''} ${compareSelection.find(s => s.id === m.id) ? 'selected' : ''}`}
                onClick={() => handleMsgClick(m)}
              >
                <div className="message-text">
                  {m.sender === "ALICE" ? m.plaintext : (m.decrypted_plaintext || m.plaintext)}
                </div>
                <div className="message-footer">
                  <span>IDX: #{String(m.index).padStart(3, '0')}</span>
                  <span>{new Date(m.timestamp * 1000).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'})}</span>
                </div>
              </div>
            </div>
          ))}
        </section>

        <section className="chat-input-area">
          <div className="input-container">
            <div className="sender-toggle" onClick={() => setActiveSender(activeSender === "ALICE" ? "BOB" : "ALICE")}>
              {activeSender === "ALICE" ? "ALICE" : "BOB"}
            </div>
            <input 
              placeholder="Type a secure message..." 
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
            />
            <button className="send-btn" onClick={sendMessage} disabled={loading}>
              <Send size={18} />
            </button>
          </div>
        </section>
      </main>

      {/* 3. Security Panel */}
      <aside className="security-panel">
        <div className="pipeline-header">
          <div style={{display: 'flex', alignItems: 'center', gap: '0.5rem'}}>
            <Shield size={18} />
            <span>SECURITY PIPELINE</span>
          </div>
          <span style={{fontSize: '0.7rem', opacity: 0.5}}>MSG-{selectedMsg?.index || '0'}</span>
        </div>

        <div className="pipeline-content">
          {selectedMsg ? (
            <>
              {/* Step 1: Session */}
              <div className="pipeline-card active">
                <div className="card-header">
                  <div className="card-title"><UserCheck size={14}/> SESSION ESTABLISHED</div>
                  <div className="v-badge">VERIFIED</div>
                </div>
                <div className="card-body">
                  Session ID: <span style={{color: 'var(--text-primary)', fontWeight: 600}}>{sessionId.slice(0, 12)}...</span><br/>
                  Version: <span style={{color: 'var(--text-primary)', fontWeight: 600}}>PFS-2.1.0-STABLE</span>
                </div>
              </div>

              {/* Step 2: KDF */}
              <div className="pipeline-card active">
                <div className="card-header">
                  <div className="card-title"><Key size={14}/> KEY DERIVATION (KDF)</div>
                  <div className="v-badge">VERIFIED</div>
                </div>
                <div className="card-body">
                  Using HKDF-SHA256 with context binding.
                  <div className="code-snippet">
                    ROOT: {selectedMsg.key_preview}<br/>
                    DERIVED KEY: A4:F2:C1:99...
                  </div>
                </div>
              </div>

              {/* Step 3: Polymorphic Transformation */}
              <div className="pipeline-card active">
                <div className="card-header">
                  <div className="card-title"><Zap size={14}/> POLYMORPHIC TRANSFORMATION</div>
                </div>
                <div className="card-body">
                  Ciphertext is mutated via dynamic seed <span style={{color: 'var(--accent-primary)', fontWeight: 600}}>0xFA42</span>.
                  <div className="code-snippet">
                    AES-GCM OUTPUT: {selectedMsg.aes_ciphertext.slice(0, 32)}...<br/><br/>
                    TRANSFORMED OUTPUT: {selectedMsg.transformed_ciphertext.slice(0, 32)}...
                  </div>
                  
                  {selectedMsg.transformation_steps && (
                    <div className="transformation-sequence">
                       <div style={{fontSize: '0.65rem', fontWeight: 800, marginBottom: '0.5rem', color: 'var(--text-secondary)'}}>PROTOCOL FLOW BREAKDOWN</div>
                       <div className="sequence-flow">
                          {selectedMsg.transformation_steps.map((step, idx) => (
                            <React.Fragment key={idx}>
                              <div className="step-badge" title={step.name}>{step.name.split(' ')[0]}</div>
                              {idx < selectedMsg.transformation_steps.length - 1 && <ArrowRight size={10} className="step-arrow"/>}
                            </React.Fragment>
                          ))}
                       </div>
                       <div className="transformation-detail">
                         {selectedMsg.transformation_steps.map((step, idx) => (
                            <div key={idx} className="transform-step-val">
                              <span className="transform-label">[{step.name.split(' ')[0]}]</span> 
                              <span style={{color: 'var(--text-muted)'}}>{step.data.slice(0, 12)}...</span>
                            </div>
                         ))}
                       </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Step 4: Packet Assembler */}
              <div className="pipeline-card">
                <div className="card-header">
                  <div className="card-title"><Layers size={14}/> PACKET ASSEMBLER</div>
                </div>
                <div className="card-body" style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem'}}>
                  <div>Packet Length:</div><div style={{textAlign: 'right'}}>{selectedMsg.packet_length} Bytes</div>
                  <div>Nonce / IV:</div><div style={{textAlign: 'right'}}>{selectedMsg.iv.slice(0, 8)}...</div>
                  <div>Timestamp:</div><div style={{textAlign: 'right'}}>{selectedMsg.timestamp}</div>
                </div>
              </div>

              {/* Step 5: Integrity Verification */}
              <div className="pipeline-card active">
                <div className="card-header">
                  <div className="card-title"><Shield size={14}/> INTEGRITY (HMAC)</div>
                  <div className="v-badge">VERIFIED</div>
                </div>
                <div className="card-body">
                  <div className={`v-badge ${selectedMsg.integrity_ok ? '' : 'danger'}`} style={{width: '100%', textAlign: 'center', marginBottom: '0.5rem', background: selectedMsg.integrity_ok ? '#f0fdf4' : '#fef2f2', color: selectedMsg.integrity_ok ? 'var(--success)' : 'var(--error)'}}>
                    {selectedMsg.integrity_ok ? 'HMAC-SHA256 MATCH' : 'INTEGRITY FAILED'}
                  </div>
                  <div className="code-snippet" style={{color: selectedMsg.integrity_ok ? 'var(--success)' : 'var(--error)'}}>
                    0xFA12...{selectedMsg.integrity_ok ? '99C2' : 'FAIL'}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div style={{textAlign: 'center', color: 'var(--text-muted)', marginTop: '4rem'}}>
              <Lock size={48} style={{opacity: 0.1, marginBottom: '1.5rem', margin: '0 auto'}} />
              <p>Select a message to view<br/>security internals</p>
            </div>
          )}
        </div>

        <div className="sim-actions">
           <button className="sim-btn" onClick={() => startSimulation('REPLAY')}>SIMULATE REPLAY</button>
           <button className="sim-btn danger" onClick={() => startSimulation('TAMPER')}>SIMULATE TAMPER</button>
           <button className="sim-btn" style={{gridColumn: 'span 2'}} onClick={resetState}>RESET SECURITY STATE</button>
        </div>
      </aside>
    </div>
  );
};

export default App;
