import { useState, useCallback } from "react";

const stripCites = (text) => {
  if (!text) return text;
  return text.replace(/]*>(.*?)<\/antml:cite>/gs, '$1')
             .replace(/]*>/g, '')
             .replace(/<\/antml:cite>/g, '')
             .trim();
};

const SYSTEM_PROMPT = `You are ThreatLens, an expert cybersecurity threat intelligence analyst. Your task is to analyze cybersecurity threats and produce structured intelligence reports.

When given a threat topic or query, you MUST:
1. Search for recent cybersecurity threat intelligence using web search
2. Analyze and summarize the threats found
3. Return ONLY a valid JSON object (no markdown, no backticks, no preamble, no <cite> tags, no citation markup of any kind)

Return this exact JSON structure:
{
  "report_title": "string - concise title for this threat intelligence report",
  "generated_at": "string - ISO timestamp",
  "threat_landscape_summary": "string - 2-3 sentence executive summary of the current threat landscape",
  "threats": [
    {
      "id": "string - e.g. TL-001",
      "name": "string - threat name",
      "threat_actor": "string - APT group, criminal org, or Unknown",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "severity_score": number between 1-10,
      "category": "Ransomware|Phishing|APT|Vulnerability|Malware|Supply Chain|Social Engineering|DDoS|Insider Threat|Zero-Day",
      "summary": "string - 2-3 sentence threat description",
      "affected_industries": ["array of affected sectors"],
      "healthcare_relevance": "HIGH|MEDIUM|LOW|NONE",
      "healthcare_context": "string - specific healthcare/HIPAA implications if any, else null",
      "mitre_attack": {
        "tactics": ["array of MITRE ATT&CK tactic names"],
        "techniques": [
          {
            "id": "string - e.g. T1566.001",
            "name": "string - technique name",
            "description": "string - brief description of how this technique applies"
          }
        ]
      },
      "iocs": {
        "cves": ["array of CVE IDs if any"],
        "indicators": ["array of behavioral IOCs"],
        "domains_or_ips": ["array of known malicious domains/IPs if any"]
      },
      "recommended_actions": ["array of 3-4 specific mitigation steps"],
      "source": "string - source publication name",
      "source_url": "string - URL if available"
    }
  ],
  "healthcare_alert": "string - specific alert for healthcare sector defenders, or null",
  "top_mitre_tactics": ["array of most prevalent tactics across all threats"],
  "total_threats_analyzed": number,
  "analyst_note": "string - one key insight from D'Anthony Carter-Marshall, Cybersecurity Analyst perspective on operational healthcare impact"
}

Use web search to find real, current threat intelligence. Focus on threats from the last 30-90 days. If the query mentions healthcare, prioritize HIPAA, PHI, and medical device threats.`;

const SEVERITY_CONFIG = {
  CRITICAL: { bg: "var(--color-background-danger)", text: "var(--color-text-danger)", border: "var(--color-border-danger)" },
  HIGH: { bg: "#FAEEDA", text: "#854F0B", border: "#EF9F27" },
  MEDIUM: { bg: "#EAF3DE", text: "#3B6D11", border: "#639922" },
  LOW: { bg: "var(--color-background-secondary)", text: "var(--color-text-secondary)", border: "var(--color-border-tertiary)" }
};

const HEALTHCARE_CONFIG = {
  HIGH: { bg: "#FCEBEB", text: "#A32D2D", border: "#E24B4A", label: "High Healthcare Risk" },
  MEDIUM: { bg: "#FAEEDA", text: "#854F0B", border: "#EF9F27", label: "Medium Healthcare Risk" },
  LOW: { bg: "#EAF3DE", text: "#3B6D11", border: "#639922", label: "Low Healthcare Risk" },
  NONE: { bg: "var(--color-background-secondary)", text: "var(--color-text-tertiary)", border: "var(--color-border-tertiary)", label: "No Direct Impact" }
};

const SAMPLE_QUERIES = [
  "Healthcare ransomware threats Q1 2026",
  "Iranian APT attacks on US hospitals",
  "CISA KEV critical vulnerabilities 2026",
  "Phishing campaigns targeting healthcare workers",
  "Supply chain attacks on medical devices"
];

const CATEGORY_COLORS = {
  Ransomware: "#A32D2D",
  Phishing: "#854F0B",
  APT: "#533AB7",
  Vulnerability: "#185FA5",
  Malware: "#993C1D",
  "Supply Chain": "#3B6D11",
  "Social Engineering": "#72243E",
  DDoS: "#0F6E56",
  "Insider Threat": "#444441",
  "Zero-Day": "#A32D2D"
};

function Badge({ children, style = {} }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", padding: "2px 8px",
      borderRadius: "var(--border-radius-md)", fontSize: "11px", fontWeight: 500,
      border: "0.5px solid", ...style
    }}>
      {children}
    </span>
  );
}

function ThreatCard({ threat, isExpanded, onToggle }) {
  const sev = SEVERITY_CONFIG[threat.severity] || SEVERITY_CONFIG.LOW;
  const hc = HEALTHCARE_CONFIG[threat.healthcare_relevance] || HEALTHCARE_CONFIG.NONE;
  const catColor = CATEGORY_COLORS[threat.category] || "#444441";

  return (
    <div style={{
      background: "var(--color-background-primary)",
      border: "0.5px solid var(--color-border-tertiary)",
      borderRadius: "var(--border-radius-lg)",
      marginBottom: "12px",
      overflow: "hidden",
      transition: "box-shadow 0.15s"
    }}>
      <div
        onClick={onToggle}
        style={{
          padding: "16px 20px", cursor: "pointer",
          display: "flex", alignItems: "flex-start", gap: "12px"
        }}
      >
        <div style={{
          minWidth: "44px", height: "44px", borderRadius: "var(--border-radius-md)",
          background: sev.bg, border: `0.5px solid ${sev.border}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          flexDirection: "column"
        }}>
          <span style={{ fontSize: "11px", fontWeight: 500, color: sev.text, lineHeight: 1 }}>
            {threat.severity_score}
          </span>
          <span style={{ fontSize: "9px", color: sev.text, lineHeight: 1, marginTop: "2px" }}>
            /10
          </span>
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginBottom: "4px" }}>
            <span style={{ fontSize: "11px", fontWeight: 500, color: "var(--color-text-tertiary)", fontFamily: "var(--font-mono)" }}>
              {threat.id}
            </span>
            <Badge style={{ background: sev.bg, color: sev.text, borderColor: sev.border }}>
              {threat.severity}
            </Badge>
            <Badge style={{ background: `${catColor}15`, color: catColor, borderColor: `${catColor}40` }}>
              {threat.category}
            </Badge>
            {threat.healthcare_relevance !== "NONE" && (
              <Badge style={{ background: hc.bg, color: hc.text, borderColor: hc.border }}>
                + Healthcare
              </Badge>
            )}
          </div>
          <p style={{ margin: 0, fontSize: "14px", fontWeight: 500, color: "var(--color-text-primary)" }}>
            {threat.name}
          </p>
          <p style={{ margin: "4px 0 0", fontSize: "12px", color: "var(--color-text-secondary)" }}>
            {threat.threat_actor !== "Unknown" && <span>Actor: {threat.threat_actor} · </span>}
            {stripCites(threat.summary).slice(0, 120)}...
          </p>
        </div>

        <span style={{
          fontSize: "16px", color: "var(--color-text-secondary)",
          transform: isExpanded ? "rotate(180deg)" : "rotate(0deg)",
          transition: "transform 0.2s", flexShrink: 0, marginTop: "4px"
        }}>▾</span>
      </div>

      {isExpanded && (
        <div style={{ padding: "0 20px 20px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>
          <div style={{ paddingTop: "16px" }}>
            <p style={{ fontSize: "13px", color: "var(--color-text-primary)", lineHeight: 1.7, margin: "0 0 16px" }}>
              {stripCites(threat.summary)}
            </p>

            {threat.healthcare_relevance !== "NONE" && threat.healthcare_context && (
              <div style={{
                background: hc.bg, border: `0.5px solid ${hc.border}`,
                borderRadius: "var(--border-radius-md)", padding: "12px",
                marginBottom: "16px"
              }}>
                <p style={{ fontSize: "11px", fontWeight: 500, color: hc.text, margin: "0 0 4px" }}>
                  Healthcare / HIPAA Impact
                </p>
                <p style={{ fontSize: "12px", color: hc.text, margin: 0, lineHeight: 1.6 }}>
                  {stripCites(threat.healthcare_context)}
                </p>
              </div>
            )}

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
              <div>
                <p style={{ fontSize: "11px", fontWeight: 500, color: "var(--color-text-secondary)", margin: "0 0 8px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                  Affected Industries
                </p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                  {threat.affected_industries.map(ind => (
                    <Badge key={ind} style={{ background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", borderColor: "var(--color-border-tertiary)" }}>
                      {ind}
                    </Badge>
                  ))}
                </div>
              </div>
              <div>
                <p style={{ fontSize: "11px", fontWeight: 500, color: "var(--color-text-secondary)", margin: "0 0 8px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                  IOCs & CVEs
                </p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                  {[...(threat.iocs?.cves || []), ...(threat.iocs?.indicators?.slice(0, 3) || [])].map((ioc, i) => (
                    <Badge key={i} style={{ background: "#E6F1FB", color: "#185FA5", borderColor: "#85B7EB", fontFamily: "var(--font-mono)", fontSize: "10px" }}>
                      {ioc}
                    </Badge>
                  ))}
                  {!threat.iocs?.cves?.length && !threat.iocs?.indicators?.length && (
                    <span style={{ fontSize: "12px", color: "var(--color-text-tertiary)" }}>None identified</span>
                  )}
                </div>
              </div>
            </div>

            <div style={{ marginBottom: "16px" }}>
              <p style={{ fontSize: "11px", fontWeight: 500, color: "var(--color-text-secondary)", margin: "0 0 8px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                MITRE ATT&CK Mapping
              </p>
              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "8px" }}>
                {threat.mitre_attack?.tactics?.map(tactic => (
                  <Badge key={tactic} style={{ background: "#EEEDFE", color: "#3C3489", borderColor: "#AFA9EC" }}>
                    {tactic}
                  </Badge>
                ))}
              </div>
              {threat.mitre_attack?.techniques?.map(tech => (
                <div key={tech.id} style={{
                  background: "var(--color-background-secondary)",
                  borderRadius: "var(--border-radius-md)",
                  padding: "8px 12px", marginBottom: "6px",
                  display: "flex", gap: "10px", alignItems: "flex-start"
                }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "#533AB7", fontWeight: 500, minWidth: "70px" }}>
                    {tech.id}
                  </span>
                  <div>
                    <p style={{ margin: 0, fontSize: "12px", fontWeight: 500, color: "var(--color-text-primary)" }}>{tech.name}</p>
                    <p style={{ margin: "2px 0 0", fontSize: "11px", color: "var(--color-text-secondary)" }}>{stripCites(tech.description)}</p>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ marginBottom: "12px" }}>
              <p style={{ fontSize: "11px", fontWeight: 500, color: "var(--color-text-secondary)", margin: "0 0 8px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                Recommended Actions
              </p>
              {threat.recommended_actions?.map((action, i) => (
                <div key={i} style={{ display: "flex", gap: "10px", alignItems: "flex-start", marginBottom: "6px" }}>
                  <span style={{
                    width: "20px", height: "20px", borderRadius: "50%",
                    background: "#EAF3DE", color: "#3B6D11",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: "10px", fontWeight: 500, flexShrink: 0, marginTop: "1px"
                  }}>{i + 1}</span>
                  <p style={{ margin: 0, fontSize: "12px", color: "var(--color-text-primary)", lineHeight: 1.6 }}>{stripCites(action)}</p>
                </div>
              ))}
            </div>

            {threat.source && (
              <p style={{ fontSize: "11px", color: "var(--color-text-tertiary)", margin: 0 }}>
                Source: {threat.source_url ? (
                  <a href={threat.source_url} style={{ color: "var(--color-text-info)" }}>{threat.source}</a>
                ) : threat.source}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ThreatLens() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [loadingMessage, setLoadingMessage] = useState("");
  const [filterSev, setFilterSev] = useState("ALL");
  const [filterHC, setFilterHC] = useState(false);

  const LOADING_MESSAGES = [
    "Scanning live threat intelligence feeds...",
    "Correlating MITRE ATT&CK techniques...",
    "Assessing healthcare sector exposure...",
    "Extracting IOCs and threat indicators...",
    "Generating analyst briefing..."
  ];

  const runAnalysis = useCallback(async (searchQuery) => {
    if (!searchQuery.trim()) return;
    setLoading(true);
    setReport(null);
    setError(null);
    setExpandedId(null);
    setFilterSev("ALL");
    setFilterHC(false);

    let msgIdx = 0;
    setLoadingMessage(LOADING_MESSAGES[0]);
    const msgInterval = setInterval(() => {
      msgIdx = (msgIdx + 1) % LOADING_MESSAGES.length;
      setLoadingMessage(LOADING_MESSAGES[msgIdx]);
    }, 2200);

    try {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
        "Content-Type": "application/json",
        "x-api-key": import.meta.env.VITE_ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "anthropic-dangerous-direct-browser-access": "true",
      },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 4000,
          system: SYSTEM_PROMPT,
          tools: [{ type: "web_search_20250305", name: "web_search" }],
          messages: [{
            role: "user",
            content: `Generate a comprehensive threat intelligence report for: "${searchQuery}". Use web search to find real, current threats from the past 90 days. Return ONLY the JSON object with no markdown formatting.`
          }]
        })
      });

      const data = await response.json();

      let jsonText = "";
      for (const block of data.content) {
        if (block.type === "text" && block.text) {
          jsonText = block.text;
          break;
        }
      }

      const clean = jsonText.replace(/```json|```/g, "").trim();
      const parsed = JSON.parse(clean);
      setReport(parsed);
    } catch (err) {
      setError("Analysis failed. Please verify your connection and try again. Error: " + err.message);
    } finally {
      clearInterval(msgInterval);
      setLoading(false);
    }
  }, []);

  const handleSubmit = () => runAnalysis(query);
  const handleSample = (q) => { setQuery(q); runAnalysis(q); };

  const filteredThreats = report?.threats?.filter(t => {
    if (filterSev !== "ALL" && t.severity !== filterSev) return false;
    if (filterHC && t.healthcare_relevance === "NONE") return false;
    return true;
  }) || [];

  const criticalCount = report?.threats?.filter(t => t.severity === "CRITICAL" || t.severity === "HIGH").length || 0;
  const hcCount = report?.threats?.filter(t => t.healthcare_relevance !== "NONE").length || 0;
  const avgScore = report?.threats?.length
    ? Math.round(report.threats.reduce((a, t) => a + t.severity_score, 0) / report.threats.length * 10) / 10
    : 0;

  return (
    <div style={{ fontFamily: "var(--font-sans)", maxWidth: "900px", margin: "0 auto", padding: "1.5rem 1rem" }}>

      <div style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "4px" }}>
          <div style={{
            width: "36px", height: "36px", borderRadius: "var(--border-radius-md)",
            background: "#EEEDFE", display: "flex", alignItems: "center", justifyContent: "center"
          }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v10l9 5 9-5V7L12 2z" stroke="#3C3489" strokeWidth="1.5" fill="none"/>
              <circle cx="12" cy="12" r="3" fill="#3C3489"/>
            </svg>
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: "20px", fontWeight: 500, color: "var(--color-text-primary)" }}>
              ThreatLens
            </h1>
            <p style={{ margin: 0, fontSize: "12px", color: "var(--color-text-tertiary)" }}>
              AI-Powered Threat Intelligence · MITRE ATT&CK · Healthcare Focus
            </p>
          </div>
        </div>
      </div>

      <div style={{
        background: "var(--color-background-primary)",
        border: "0.5px solid var(--color-border-tertiary)",
        borderRadius: "var(--border-radius-lg)",
        padding: "20px",
        marginBottom: "16px"
      }}>
        <p style={{ margin: "0 0 10px", fontSize: "13px", color: "var(--color-text-secondary)" }}>
          Query threat intelligence
        </p>
        <div style={{ display: "flex", gap: "8px" }}>
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSubmit()}
            placeholder="e.g. Healthcare ransomware threats, Iranian APT campaigns, CISA KEV vulnerabilities..."
            style={{ flex: 1, fontSize: "13px" }}
            disabled={loading}
          />
          <button
            onClick={handleSubmit}
            disabled={loading || !query.trim()}
            style={{ padding: "0 20px", fontSize: "13px", whiteSpace: "nowrap" }}
          >
            {loading ? "Analyzing..." : "Analyze ↗"}
          </button>
        </div>

        <div style={{ marginTop: "12px" }}>
          <p style={{ margin: "0 0 8px", fontSize: "11px", color: "var(--color-text-tertiary)" }}>Sample queries</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
            {SAMPLE_QUERIES.map(q => (
              <button
                key={q}
                onClick={() => handleSample(q)}
                disabled={loading}
                style={{ padding: "4px 10px", fontSize: "11px", borderRadius: "var(--border-radius-md)" }}
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading && (
        <div style={{
          background: "var(--color-background-primary)",
          border: "0.5px solid var(--color-border-tertiary)",
          borderRadius: "var(--border-radius-lg)",
          padding: "40px 20px", textAlign: "center", marginBottom: "16px"
        }}>
          <div style={{
            width: "40px", height: "40px", borderRadius: "50%",
            border: "2px solid #EEEDFE", borderTopColor: "#534AB7",
            animation: "spin 1s linear infinite", margin: "0 auto 16px"
          }} />
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          <p style={{ margin: 0, fontSize: "13px", color: "var(--color-text-secondary)" }}>{loadingMessage}</p>
          <p style={{ margin: "4px 0 0", fontSize: "11px", color: "var(--color-text-tertiary)" }}>
            Querying live threat intelligence via web search...
          </p>
        </div>
      )}

      {error && (
        <div style={{
          background: "var(--color-background-danger)",
          border: "0.5px solid var(--color-border-danger)",
          borderRadius: "var(--border-radius-lg)",
          padding: "16px 20px", marginBottom: "16px"
        }}>
          <p style={{ margin: 0, fontSize: "13px", color: "var(--color-text-danger)" }}>{error}</p>
        </div>
      )}

      {report && (
        <div>
          <div style={{
            background: "var(--color-background-primary)",
            border: "0.5px solid var(--color-border-tertiary)",
            borderRadius: "var(--border-radius-lg)",
            padding: "20px", marginBottom: "16px"
          }}>
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "12px" }}>
              <div>
                <p style={{ margin: "0 0 4px", fontSize: "11px", color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                  Intelligence Report
                </p>
                <h2 style={{ margin: 0, fontSize: "16px", fontWeight: 500, color: "var(--color-text-primary)" }}>
                  {report.report_title}
                </h2>
              </div>
              <span style={{ fontSize: "11px", color: "var(--color-text-tertiary)", whiteSpace: "nowrap", marginLeft: "12px" }}>
                {new Date(report.generated_at).toLocaleDateString()}
              </span>
            </div>

            <p style={{ margin: "0 0 16px", fontSize: "13px", color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
              {stripCites(report.threat_landscape_summary)}
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "10px", marginBottom: "12px" }}>
              {[
                { label: "Threats", value: report.total_threats_analyzed || report.threats?.length || 0 },
                { label: "High/Critical", value: criticalCount, danger: criticalCount > 0 },
                { label: "Healthcare Risk", value: hcCount, warn: hcCount > 0 },
                { label: "Avg. Score", value: avgScore + "/10" }
              ].map(stat => (
                <div key={stat.label} style={{
                  background: "var(--color-background-secondary)",
                  borderRadius: "var(--border-radius-md)",
                  padding: "12px", textAlign: "center"
                }}>
                  <p style={{
                    margin: "0 0 4px", fontSize: "20px", fontWeight: 500,
                    color: stat.danger ? "var(--color-text-danger)" : stat.warn ? "#854F0B" : "var(--color-text-primary)"
                  }}>{stat.value}</p>
                  <p style={{ margin: 0, fontSize: "11px", color: "var(--color-text-secondary)" }}>{stat.label}</p>
                </div>
              ))}
            </div>

            {report.healthcare_alert && (
              <div style={{
                background: "#FCEBEB", border: "0.5px solid #E24B4A",
                borderRadius: "var(--border-radius-md)", padding: "12px"
              }}>
                <p style={{ margin: "0 0 4px", fontSize: "11px", fontWeight: 500, color: "#A32D2D" }}>
                  Healthcare Sector Alert
                </p>
                <p style={{ margin: 0, fontSize: "12px", color: "#A32D2D", lineHeight: 1.6 }}>
                  {stripCites(report.healthcare_alert)}
                </p>
              </div>
            )}
          </div>

          {report.analyst_note && (
            <div style={{
              background: "#EEEDFE", border: "0.5px solid #AFA9EC",
              borderRadius: "var(--border-radius-lg)", padding: "16px 20px",
              marginBottom: "16px"
            }}>
              <p style={{ margin: "0 0 4px", fontSize: "11px", fontWeight: 500, color: "#3C3489" }}>
                Analyst Note — D'Anthony Carter-Marshall
              </p>
              <p style={{ margin: 0, fontSize: "12px", color: "#534AB7", lineHeight: 1.7 }}>
                {stripCites(report.analyst_note)}
              </p>
            </div>
          )}

          <div style={{ display: "flex", gap: "8px", marginBottom: "12px", flexWrap: "wrap" }}>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => (
              <button
                key={sev}
                onClick={() => setFilterSev(sev)}
                style={{
                  padding: "4px 12px", fontSize: "11px",
                  background: filterSev === sev ? (sev === "ALL" ? "#EEEDFE" : SEVERITY_CONFIG[sev]?.bg || "#EEEDFE") : "transparent",
                  color: filterSev === sev ? (sev === "ALL" ? "#3C3489" : SEVERITY_CONFIG[sev]?.text || "#3C3489") : "var(--color-text-secondary)",
                  borderColor: filterSev === sev ? (sev === "ALL" ? "#AFA9EC" : SEVERITY_CONFIG[sev]?.border || "#AFA9EC") : "var(--color-border-tertiary)"
                }}
              >
                {sev}
              </button>
            ))}
            <button
              onClick={() => setFilterHC(!filterHC)}
              style={{
                padding: "4px 12px", fontSize: "11px", marginLeft: "auto",
                background: filterHC ? "#FCEBEB" : "transparent",
                color: filterHC ? "#A32D2D" : "var(--color-text-secondary)",
                borderColor: filterHC ? "#E24B4A" : "var(--color-border-tertiary)"
              }}
            >
              Healthcare only
            </button>
          </div>

          <div>
            <p style={{ margin: "0 0 10px", fontSize: "12px", color: "var(--color-text-tertiary)" }}>
              Showing {filteredThreats.length} of {report.threats?.length} threats — click to expand
            </p>
            {filteredThreats.map(threat => (
              <ThreatCard
                key={threat.id}
                threat={threat}
                isExpanded={expandedId === threat.id}
                onToggle={() => setExpandedId(expandedId === threat.id ? null : threat.id)}
              />
            ))}
          </div>

          {report.top_mitre_tactics?.length > 0 && (
            <div style={{
              background: "var(--color-background-primary)",
              border: "0.5px solid var(--color-border-tertiary)",
              borderRadius: "var(--border-radius-lg)",
              padding: "16px 20px", marginTop: "8px"
            }}>
              <p style={{ margin: "0 0 10px", fontSize: "11px", fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                Prevalent MITRE ATT&CK Tactics
              </p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {report.top_mitre_tactics.map(tactic => (
                  <Badge key={tactic} style={{ background: "#EEEDFE", color: "#3C3489", borderColor: "#AFA9EC", padding: "4px 10px" }}>
                    {tactic}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {!report && !loading && !error && (
        <div style={{
          background: "var(--color-background-secondary)",
          borderRadius: "var(--border-radius-lg)",
          padding: "40px 20px", textAlign: "center"
        }}>
          <svg width="40" height="40" viewBox="0 0 40 40" style={{ margin: "0 auto 12px", display: "block" }}>
            <polygon points="20,4 36,32 4,32" fill="#EEEDFE" stroke="#AFA9EC" strokeWidth="1"/>
            <circle cx="20" cy="22" r="3" fill="#534AB7"/>
            <line x1="20" y1="13" x2="20" y2="19" stroke="#534AB7" strokeWidth="2" strokeLinecap="round"/>
          </svg>
          <p style={{ margin: "0 0 4px", fontSize: "14px", fontWeight: 500, color: "var(--color-text-primary)" }}>
            Ready for threat analysis
          </p>
          <p style={{ margin: 0, fontSize: "12px", color: "var(--color-text-secondary)" }}>
            Enter a query above or select a sample to generate a live intelligence report
          </p>
        </div>
      )}

      <div style={{ marginTop: "20px", padding: "12px", textAlign: "center" }}>
        <p style={{ margin: 0, fontSize: "11px", color: "var(--color-text-tertiary)" }}>
          ThreatLens · Built by D'Anthony Carter-Marshall · CompTIA Security+ ·{" "}
          <a href="https://github.com/dcartermarshall" style={{ color: "var(--color-text-info)" }}>
            github.com/dcartermarshall
          </a>
        </p>
      </div>
    </div>
  );
}
