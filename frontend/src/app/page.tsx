"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { apiRequest } from "@/lib/api";

import {
  Activity,
  Bell,
  Bot,
  BrainCircuit,
  ChartNoAxesCombined,
  FileText,
  Gauge,
  LayoutDashboard,
  LogOut,
  Radar,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Siren,
  Terminal,
  UserRound,
  Workflow,
} from "lucide-react";

const menuItems = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Incidents", icon: Siren },
  { name: "Security Alerts", icon: Bell },
  { name: "AI Investigation", icon: BrainCircuit },
  { name: "MITRE ATT&CK", icon: Radar },
  { name: "Threat Intelligence", icon: Activity },
  { name: "Machine Learning", icon: ChartNoAxesCombined },
  { name: "SOAR Actions", icon: Workflow },
  { name: "Reports", icon: FileText },
  { name: "Analyst Assistant", icon: Bot },
  { name: "Monitoring", icon: Gauge },
];

type DashboardMetrics = {
  operational: {
    total_incidents: number;
    incidents_with_mttd: number;
    incidents_with_mttr: number;
    average_mttd_seconds: number | null;
    average_mttr_seconds: number | null;
  };


  quality: {
    reviewed_incidents: number;
    true_positive_count: number;
    false_positive_count: number;
    false_positive_rate: number | null;
  };
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
};

type CurrentUser = {
  id: number;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
};

type Incident = {
  id: number;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  disposition:
    | "unknown"
    | "true_positive"
    | "false_positive"
    | "benign";
  source: string | null;
  hostname: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  assigned_to: string | null;
  correlation_id: string | null;
  event_timestamp: string | null;
  detected_at: string;
  resolved_at: string | null;
  created_at: string;
  workflow_status: string;
  workflow_error: string | null;
};

type AIAnalysis = {
  id: number;
  incident_id: number;
  summary: string;
  risk_level: string;
  explanation: string | null;
  recommendation: string | null;
  mitre_technique: string | null;
  mitre_name: string | null;
  mitre_valid: boolean;
  rag_sources: string[] | null;
  human_approval_required: boolean;
  human_approved: boolean | null;
  human_review_status: string | null;
  human_comment: string | null;
  response_status: string | null;
  thread_id: string | null;
  agent_trace: string[] | null;
  model_used: string | null;
  created_at: string;
};

type SOARAction = {
  id: number;
  incident_id: number;
  action_type: string;
  target: string;
  status: string;
  requires_approval: boolean;
  approved: boolean | null;
  result: unknown | null;
  executed_at: string | null;
  created_at: string;
};

type AnalystResponse = {
  question: string;
  answer: string;
  sources: {
    source: string | null;
    score: number | null;
  }[];
};

type ThreatProviderResult = {
  status?: string;
  provider?: string;
  risk?: string;
  error?: string;
  reason?: string;

  // AbuseIPDB
  abuse_score?: number;
  total_reports?: number;

  // VirusTotal
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  reputation?: number | null;

  // AlienVault OTX
  pulse_count?: number;
};

type ThreatIntelligenceIOC = {
  ioc_type: string;
  value: string;
  scope: string | null;
  providers: {
    abuseipdb?: ThreatProviderResult;
    virustotal?: ThreatProviderResult;
    otx?: ThreatProviderResult;
    misp?: ThreatProviderResult;
  };
};

type ThreatIntelligenceResponse = {
  incident_id: number;
  source: string | null;
  source_ip: string | null;
  destination_ip: string | null;

  extracted_iocs: {
    ips: string[];
    domains: string[];
    urls: string[];
    hashes: unknown[];
  };

  ioc_summary: {
    ips: number;
    domains: number;
    urls: number;
    hashes: number;
  };

  ioc_count: number;
  threat_intelligence: ThreatIntelligenceIOC[];
};

type MLModelResult = {
  prediction?: string | null;
  BENIGN?: number | null;
  DDoS?: number | null;
  PortScan?: number | null;
  "FTP-Patator"?: number | null;
  "SSH-Patator"?: number | null;
  is_anomaly?: boolean | null;
  anomaly_score?: number | null;
};
type SecurityAlert = {
  id: number;
  title: string;
  description: string | null;
  severity: string;
  source: string;
  status: string;
  created_at: string;
};
type SOCReport = {
  id: number;
  incident_id: number;
  ai_analysis_id: number | null;
thread_id: string | null;
title: string;
summary: string;
risk_level: string;
mitre_technique: string | null;
mitre_name: string | null;
recommendation: string | null;
response_status: string | null;
human_review_status: string | null;
human_comment: string | null;
rag_sources: string[] | null;
agent_trace: string[] | null;
  ml_status: string | null;
  ml_engine: string | null;
  ml_prediction: string | null;

  ml_probabilities: {
    random_forest?: MLModelResult;
    xgboost?: MLModelResult;
    isolation_forest?: MLModelResult;
  } | null;

  ml_is_anomaly: boolean | null;
  ml_anomaly_score: number | null;
  created_at: string;
};
  
function MetricCard({
  title,
  value,
  tone = "",
  detail,
}: {
  title: string;
  value: string;
  tone?: string;
  detail?: string;
}) {
  return (
    <div className="metric-card">
      <div className="metric-title">{title}</div>
      <div className={`metric-value ${tone}`}>{value}</div>
      {detail && <span className="metric-detail">{detail}</span>}
    </div>
  );
}

export default function Home() {
  const router = useRouter();

  const [authChecked, setAuthChecked] = useState(false);

  const [currentUser, setCurrentUser] =
  useState<CurrentUser | null>(null);

  const [metrics, setMetrics] =
    useState<DashboardMetrics | null>(null);

  const [incidents, setIncidents] =
    useState<Incident[]>([]);

  const [alerts, setAlerts] =
  useState<SecurityAlert[]>([]);  
  
  const [selectedIncident, setSelectedIncident] =
  useState<Incident | null>(null);

  const [searchQuery, setSearchQuery] = useState("");

  const [systemHealthy, setSystemHealthy] =
  useState<boolean | null>(null);

  const [activeSection, setActiveSection] =
  useState("Overview");

  const [analyses, setAnalyses] =
    useState<AIAnalysis[]>([]);

  const [reports, setReports] =
  useState<SOCReport[]>([]);

  const [soarActions, setSoarActions] =
    useState<SOARAction[]>([]);

  const [soarActionLoading, setSoarActionLoading] =
    useState<number | null>(null);

  const [soarError, setSoarError] =
    useState<string | null>(null);

  // =====================================================
  // THREAT INTELLIGENCE
  // =====================================================

  const [threatIntel, setThreatIntel] =
    useState<ThreatIntelligenceResponse | null>(null);

  const [threatIntelLoading, setThreatIntelLoading] =
    useState(false);

  const [threatIntelError, setThreatIntelError] =
    useState<string | null>(null);

  // =====================================================
  // ANALYST ASSISTANT
  // =====================================================

  const [analystQuestion, setAnalystQuestion] =
    useState("");

  const [analystAnswer, setAnalystAnswer] =
    useState<string | null>(null);

  const [analystSources, setAnalystSources] =
    useState<AnalystResponse["sources"]>([]);

  const [analystLoading, setAnalystLoading] =
    useState(false);

  const [analystError, setAnalystError] =
    useState<string | null>(null);

  // =====================================================
  // LOAD DASHBOARD
  // =====================================================

  useEffect(() => {
    async function loadDashboard() {
      const token = localStorage.getItem("access_token");

      if (!token) {
        router.replace("/login");
        return;
      }

      try {
        const userData =
  await apiRequest<CurrentUser>("/auth/me");

setCurrentUser(userData);

try {
  const healthData =
    await apiRequest<{ status: string }>("/health");

  setSystemHealthy(
    healthData.status.toLowerCase() === "healthy"
  );
} catch {
  setSystemHealthy(false);
}
        const [
  dashboardMetrics,
  incidentData,
  analysisData,
  soarData,
  reportData,
  alertData,
] = await Promise.all([
  apiRequest<DashboardMetrics>(
    "/metrics/dashboard"
  ),
  apiRequest<Incident[]>(
    "/incidents"
  ),
  apiRequest<AIAnalysis[]>(
    "/ai-analysis"
  ),
  apiRequest<SOARAction[]>(
    "/soar"
  ),
  apiRequest<SOCReport[]>(
    "/reports"
  ),

  apiRequest<SecurityAlert[]>("/alerts"),
]);

setMetrics(dashboardMetrics);
setIncidents(incidentData);
setAnalyses(analysisData);
setSoarActions(soarData);
setReports(reportData);
setAlerts(alertData);

        // ===============================================
        // LOAD TI FOR THE LATEST INCIDENT
        // ===============================================

        if (incidentData.length > 0) {
          const latestIncident = [...incidentData].sort(
            (a, b) =>
              new Date(b.detected_at).getTime() -
              new Date(a.detected_at).getTime()
          )[0];

          try {
            setThreatIntelLoading(true);
            setThreatIntelError(null);

            const tiData =
              await apiRequest<ThreatIntelligenceResponse>(
                `/threat-intelligence/incident/${latestIncident.id}`
              );

            setThreatIntel(tiData);
          } catch (error) {
            setThreatIntel(null);

            setThreatIntelError(
              error instanceof Error
                ? error.message
                : "Threat Intelligence unavailable"
            );
          } finally {
            setThreatIntelLoading(false);
          }
        } else {
          setThreatIntel(null);
        }

        setAuthChecked(true);
      } catch {
        localStorage.removeItem("access_token");
        localStorage.removeItem("soc_user");

        router.replace("/login");
      }
    }

    loadDashboard();
  }, [router]);

  // =====================================================
  // AUTH
  // =====================================================

  function handleLogout() {
    localStorage.removeItem("access_token");
    localStorage.removeItem("soc_user");

    router.replace("/login");
  }

  // =====================================================
  // FORMATTERS
  // =====================================================

  function formatDuration(
    seconds: number | null | undefined
  ) {
    if (
      seconds === null ||
      seconds === undefined
    ) {
      return "N/A";
    }

    if (seconds < 60) {
      return `${seconds.toFixed(1)}s`;
    }

    if (seconds < 3600) {
      return `${(seconds / 60).toFixed(1)}m`;
    }

    return `${(seconds / 3600).toFixed(1)}h`;
  }

  function formatDate(
    value: string | null | undefined
  ) {
    if (!value) {
      return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return "—";
    }

    return date.toLocaleString();
  }

  function getSeverityPercentage(
    severity: keyof DashboardMetrics["severity"]
  ) {
    if (!metrics) {
      return 0;
    }

    const total =
      metrics.severity.critical +
      metrics.severity.high +
      metrics.severity.medium +
      metrics.severity.low;

    if (total === 0) {
      return 0;
    }

    return (
      (metrics.severity[severity] / total) *
      100
    );
  }

  function getLatestAnalysis(
    incidentId: number
  ): AIAnalysis | undefined {
    return analyses.reduce<
      AIAnalysis | undefined
    >((latest, analysis) => {
      if (
        analysis.incident_id !== incidentId
      ) {
        return latest;
      }

      if (
        !latest ||
        analysis.id > latest.id
      ) {
        return analysis;
      }

      return latest;
    }, undefined);
  }

  function formatActionType(
    actionType: string
  ) {
    return actionType
      .replaceAll("_", " ")
      .replace(
        /\b\w/g,
        (letter) => letter.toUpperCase()
      );
  }

  // =====================================================
  // THREAT INTELLIGENCE HELPERS
  // =====================================================

  const primaryThreatIOC =
    threatIntel?.threat_intelligence.find(
      (ioc) => ioc.scope === "public"
    ) ??
    threatIntel?.threat_intelligence[0] ??
    null;

  const abuseIPDB =
    primaryThreatIOC?.providers.abuseipdb;

  const virusTotal =
    primaryThreatIOC?.providers.virustotal;

  const otx =
    primaryThreatIOC?.providers.otx;

  const misp =
    primaryThreatIOC?.providers.misp;

  function threatTone(
    risk?: string
  ) {
    switch (risk?.toUpperCase()) {
      case "MALICIOUS":
      case "CRITICAL":
      case "HIGH":
        return "red";

      case "SUSPICIOUS":
      case "MEDIUM":
        return "orange";

      case "SAFE":
      case "LOW":
        return "green";

      default:
        return "yellow";
    }
  }

  function providerStatus(
    provider?: ThreatProviderResult
  ) {
    if (!provider) {
      return "N/A";
    }

    if (
      provider.status?.toLowerCase() ===
      "error"
    ) {
      return "ERROR";
    }

    if (
      provider.status?.toLowerCase() ===
      "skipped"
    ) {
      return "SKIPPED";
    }

    if (
      provider.status?.toLowerCase() ===
      "not_configured"
    ) {
      return "NOT CONFIGURED";
    }

    return (
      provider.risk?.toUpperCase() ??
      provider.status?.toUpperCase() ??
      "N/A"
    );
  }

  function providerTone(
    provider?: ThreatProviderResult
  ) {
    const status =
      provider?.status?.toLowerCase();

    if (status === "error") {
      return "red";
    }

    if (
      status === "skipped" ||
      status === "not_configured"
    ) {
      return "yellow";
    }

    return threatTone(provider?.risk);
  }

  // =====================================================
  // SOAR
  // =====================================================

  async function handleSoarDecision(
    actionId: number,
    decision: "approve" | "reject"
  ) {
    try {
      setSoarActionLoading(actionId);
      setSoarError(null);

      const updatedAction =
        await apiRequest<SOARAction>(
          `/soar/${actionId}/${decision}`,
          {
            method: "POST",
          }
        );

      setSoarActions((current) =>
        current.map((action) =>
          action.id === updatedAction.id
            ? updatedAction
            : action
        )
      );
    } catch (error) {
      setSoarError(
        error instanceof Error
          ? error.message
          : "SOAR action failed"
      );
    } finally {
      setSoarActionLoading(null);
    }
  }

  async function handleSoarExecute(
    actionId: number
  ) {
    try {
      setSoarActionLoading(actionId);
      setSoarError(null);

      const updatedAction =
        await apiRequest<SOARAction>(
          `/soar/${actionId}/execute`,
          {
            method: "POST",
          }
        );

      setSoarActions((current) =>
        current.map((action) =>
          action.id === updatedAction.id
            ? updatedAction
            : action
        )
      );
    } catch (error) {
      setSoarError(
        error instanceof Error
          ? error.message
          : "SOAR execution failed"
      );
    } finally {
      setSoarActionLoading(null);
    }
  }

  // =====================================================
  // ANALYST ASSISTANT
  // =====================================================

  async function handleAnalystAsk() {
    const question =
      analystQuestion.trim();

    if (question.length < 3) {
      setAnalystError(
        "Please enter at least 3 characters."
      );
      return;
    }

    try {
      setAnalystLoading(true);
      setAnalystError(null);

      const response =
        await apiRequest<AnalystResponse>(
          "/analyst/ask",
          {
            method: "POST",
            body: JSON.stringify({
              question,
            }),
          }
        );

      setAnalystAnswer(response.answer);
      setAnalystSources(response.sources);
    } catch (error) {
      setAnalystError(
        error instanceof Error
          ? error.message
          : "Analyst assistant failed"
      );
    } finally {
      setAnalystLoading(false);
    }
  }

  // =====================================================
  // RECENT DATA
  // =====================================================

  const normalizedSearch = searchQuery.trim().toLowerCase();

const recentIncidents = [...incidents]
  .filter((incident) => {
    if (!normalizedSearch) {
      return true;
    }

    const analysis = getLatestAnalysis(incident.id);

    const searchableValues = [
      `INC-${String(incident.id).padStart(4, "0")}`,
      incident.title,
      incident.description,
      incident.source,
      incident.source_ip,
      incident.destination_ip,
      incident.hostname,
      incident.severity,
      incident.workflow_status,
      analysis?.mitre_technique,
      analysis?.mitre_name,
    ];

    return searchableValues.some((value) =>
      value?.toLowerCase().includes(normalizedSearch)
    );
  })
  .sort(
    (a, b) =>
      new Date(b.detected_at).getTime() -
      new Date(a.detected_at).getTime()
  )
  .slice(0, 5);

  const recentSoarActions =
    [...soarActions]
      .sort(
        (a, b) =>
          new Date(b.created_at).getTime() -
          new Date(a.created_at).getTime()
      )
      .slice(0, 4);

  const latestMLReport = [...reports]
  .filter(
    (report) =>
      report.ml_status === "success" &&
      report.ml_probabilities?.random_forest &&
      report.ml_probabilities?.xgboost &&
      report.ml_probabilities?.isolation_forest
  )
  .sort((a, b) => b.id - a.id)[0];

const recentReports = [...reports]
  .sort((a, b) => b.id - a.id)
  .slice(0, 4);  

const recentAlerts = [...alerts]
  .sort(
    (a, b) =>
      new Date(b.created_at).getTime() -
      new Date(a.created_at).getTime()
  )
  .slice(0, 5);  
const randomForest =
  latestMLReport?.ml_probabilities?.random_forest;

const xgboost =
  latestMLReport?.ml_probabilities?.xgboost;

const isolationForest =
  latestMLReport?.ml_probabilities?.isolation_forest;   

const recentMitreMappings = [...analyses]
  .filter(
    (analysis) =>
      analysis.mitre_valid &&
      analysis.mitre_technique &&
      analysis.mitre_technique !== "UNKNOWN"
  )
  .sort((a, b) => b.id - a.id)
  .filter(
    (analysis, index, array) =>
      array.findIndex(
        (item) =>
          item.mitre_technique ===
          analysis.mitre_technique
      ) === index
  )
  .slice(0, 5);  
const latestPipelineAnalysis = [...analyses]
  .filter(
    (analysis) =>
      Array.isArray(analysis.agent_trace) &&
      analysis.agent_trace.length > 0
  )
  .sort((a, b) => b.id - a.id)[0];

const latestPipelineIncident =
  latestPipelineAnalysis
    ? incidents.find(
        (incident) =>
          incident.id ===
          latestPipelineAnalysis.incident_id
      )
    : undefined;
  // =====================================================
  // AUTH LOADING
  // =====================================================

  if (!authChecked) {
    return (
      <main className="login-page">
        <div className="auth-loading">
          Verifying secure session...
        </div>
      </main>
    );
  }

  // =====================================================
  // UI
  // =====================================================

  return (
    <main className="soc-app">
      <aside className="sidebar">
        <div>
          <div className="brand">
            <Shield size={24} />

            <div>
              <strong>AETHER SOC</strong>
              <span>
                AI-POWERED ANALYST
              </span>
            </div>
          </div>

          <nav className="nav">
            {menuItems.map(({ name, icon: Icon }) => (
  <button
    className={`nav-item ${
      activeSection === name ? "active" : ""
    }`}
    key={name}
    onClick={() => {
  setActiveSection(name);

  if (name === "Incidents") {
    document
      .getElementById("incidents")
      ?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
  }
  if (name === "Security Alerts") {
  document
    .getElementById("security-alerts")
    ?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
}
  if (name === "AI Investigation") {
  document
    .getElementById("ai-investigation")
    ?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
}
  if (name === "MITRE ATT&CK") {
  document
    .getElementById("mitre-attack")
    ?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
}
  if (name === "Threat Intelligence") {
  document
    .getElementById("threat-intelligence")
    ?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
}
  if (name === "Machine Learning") {
  document
    .getElementById("machine-learning")
    ?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
}
  if (name === "SOAR Actions") {
  document
    .getElementById("soar-actions")
    ?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
}
  if (name === "Reports") {
  document
    .getElementById("reports")
    ?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
}
  if (name === "Analyst Assistant") {
  document
    .getElementById("analyst-assistant")
    ?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
}
  if (name === "Monitoring") {
  document
    .getElementById("monitoring")
    ?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
}
  if (name === "Overview") {
    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  }
}}
  >
                  <Icon size={17} />
                  <span>{name}</span>
                </button>
              )
            )}
          </nav>
        </div>

        <div className="sidebar-bottom">
          <button className="nav-item">
            <Settings size={17} />
            <span>Settings</span>
          </button>

          <button
            className="nav-item"
            onClick={handleLogout}
          >
            <LogOut size={17} />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div className="search-box">
            <Search size={17} />

            <input
  value={searchQuery}
  onChange={(event) => setSearchQuery(event.target.value)}
  placeholder="Search incidents, IPs, hosts or MITRE..."
  aria-label="Search"
/>
          </div>
          <div className="top-actions">
          <div className="system-status">
  <span className="status-dot" />
  {systemHealthy === null
    ? "CHECKING SYSTEMS"
    : systemHealthy
      ? "SYSTEMS NOMINAL"
      : "SYSTEM DEGRADED"}
</div>

            <button
  className="icon-button"
  aria-label="Notifications"
  title="Notifications are not configured"
>
  <Bell size={18} />
</button>

            <div className="analyst">
              <div className="avatar">
                <UserRound size={19} />
              </div>

              <div>
                <strong>
  {currentUser?.full_name ?? "SOC User"}
</strong>

<span>
  {currentUser?.role
    ? currentUser.role.toUpperCase()
    : "UNKNOWN ROLE"}
</span>
              </div>
            </div>
          </div>
        </header>

        <div className="dashboard">
          {/* =========================================== */}
          {/* METRICS */}
          {/* =========================================== */}

          <section className="metrics-grid">
            <MetricCard
              title="TOTAL INCIDENTS"
              value={String(
                metrics?.operational
                  .total_incidents ?? 0
              )}
            />

            <MetricCard
              title="CRITICAL ALERTS"
              value={String(
                metrics?.severity
                  .critical ?? 0
              )}
              tone="red"
            />

            <MetricCard
              title="HIGH ALERTS"
              value={String(
                metrics?.severity.high ??
                  0
              )}
              tone="orange"
            />

            <MetricCard
              title="MEDIUM ALERTS"
              value={String(
                metrics?.severity.medium ??
                  0
              )}
              tone="yellow"
            />

            <MetricCard
              title="MEAN TIME TO DETECT"
              value={formatDuration(
                metrics?.operational
                  .average_mttd_seconds
              )}
              tone="cyan"
            />

            <MetricCard
              title="MEAN TIME TO RESPOND"
              value={formatDuration(
                metrics?.operational
                  .average_mttr_seconds
              )}
              tone="cyan"
            />
          </section>

          {/* =========================================== */}
          {/* OVERVIEW */}
          {/* =========================================== */}

          <section className="overview-grid">
            <article
  id="ai-investigation"
  className="panel"
>
              <h2>
                <Activity size={18} />
                INCIDENT SEVERITY OVERVIEW
              </h2>

              <div className="severity-bar">
                <span
                  className="critical-bar"
                  style={{
                    width: `${getSeverityPercentage(
                      "critical"
                    )}%`,
                  }}
                />

                <span
                  className="high-bar"
                  style={{
                    width: `${getSeverityPercentage(
                      "high"
                    )}%`,
                  }}
                />

                <span
                  className="medium-bar"
                  style={{
                    width: `${getSeverityPercentage(
                      "medium"
                    )}%`,
                  }}
                />

                <span
                  className="low-bar"
                  style={{
                    width: `${getSeverityPercentage(
                      "low"
                    )}%`,
                  }}
                />
              </div>

              <div className="legend">
                <span>
                  <i className="dot critical-dot" />
                  Critical (
                  {metrics?.severity
                    .critical ?? 0}
                  )
                </span>

                <span>
                  <i className="dot high-dot" />
                  High (
                  {metrics?.severity.high ??
                    0}
                  )
                </span>

                <span>
                  <i className="dot medium-dot" />
                  Medium (
                  {metrics?.severity
                    .medium ?? 0}
                  )
                </span>

                <span>
                  <i className="dot low-dot" />
                  Low (
                  {metrics?.severity.low ??
                    0}
                  )
                </span>
              </div>
            </article>

            <article className="panel">
              <h2>
                <BrainCircuit size={18} />
                AI INVESTIGATION PIPELINE
              </h2>

              {latestPipelineAnalysis ? (
  <>
    <div className="pipeline">
      {[
        "Triage",
        "Machine Learning",
        "Threat Intelligence",
        "Investigation",
        "Human Review",
        "Response",
        "Report",
      ].map((step, index, steps) => {
        const completed =
          latestPipelineAnalysis.agent_trace?.includes(step) ??
          false;

        return (
          <div
            key={step}
            className={`pipeline-part ${
              completed ? "active" : ""
            }`}
          >
            <span>{step}</span>

            {index < steps.length - 1 && (
              <b>→</b>
            )}
          </div>
        );
      })}
    </div>

    <p className="risk-index">
      Current Pipeline Status:{" "}
      <strong>
        {latestPipelineIncident?.workflow_status
          ? latestPipelineIncident.workflow_status
              .replaceAll("_", " ")
              .toUpperCase()
          : "UNKNOWN"}
        {" · "}
        Risk:{" "}
        {latestPipelineAnalysis.risk_level
          ?.toUpperCase() ?? "UNKNOWN"}
      </strong>
    </p>
  </>
) : (
  <p className="risk-index">
    No AI investigation workflow available
  </p>
)} 
                
            </article>
          </section>

          {/* =========================================== */}
          {/* INCIDENTS */}
          {/* =========================================== */}
           
          {/* =========================================== */}
{/* SECURITY ALERTS */}
{/* =========================================== */}

<article
  id="security-alerts"
  className="panel"
>
  <h2>
    <Bell size={18} />
    SECURITY ALERTS
  </h2>

  {recentAlerts.length === 0 ? (
    <div
      style={{
        padding: "20px 0",
        opacity: 0.65,
        fontSize: "12px",
      }}
    >
      No security alerts available.
    </div>
  ) : (
    recentAlerts.map((alert) => (
      <div
        className="soar-row"
        key={alert.id}
      >
        <div>
          <strong>{alert.title}</strong>

          <small>
            {alert.source}
            {" · "}
            {alert.status}
            {" · "}
            {formatDate(alert.created_at)}
          </small>
        </div>

        <b
          className={
            alert.severity.toLowerCase() === "critical" ||
            alert.severity.toLowerCase() === "high"
              ? "red"
              : alert.severity.toLowerCase() === "medium"
                ? "yellow"
                : "green"
          }
        >
          {alert.severity.toUpperCase()}
        </b>
      </div>
    ))
  )}
</article> 

          <article
  id="incidents"
  className="panel incidents-panel"
>
            <h2>
              <ShieldAlert size={18} />
              RECENT SECURITY INCIDENTS
            </h2>

            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>INCIDENT ID</th>
                    <th>TITLE</th>
                    <th>SOURCE</th>
                    <th>SEVERITY</th>
                    <th>AI RISK</th>
                    <th>
                      MITRE TECHNIQUE
                    </th>
                    <th>STATUS</th>
                    <th>
                      DETECTION TIME
                    </th>
                    <th>ACTION</th>
                  </tr>
                </thead>

                <tbody>
                  {recentIncidents.length ===
                  0 ? (
                    <tr>
                      <td
                        colSpan={9}
                        className="empty-state"
                      >
                        No security incidents
                        found.
                      </td>
                    </tr>
                  ) : (
                    recentIncidents.map(
                      (incident) => {
                        const analysis =
                          getLatestAnalysis(
                            incident.id
                          );

                        const aiRisk =
                          analysis?.risk_level
                            ?.trim()
                            .toLowerCase();

                        const mitre =
                          analysis?.mitre_technique;

                        const mitreName =
                          analysis?.mitre_name;

                        const workflowClass =
                          incident.workflow_status
                            ?.toLowerCase()
                            .replaceAll(
                              " ",
                              "-"
                            ) ||
                          "unknown";

                        return (
                          <tr
                            key={
                              incident.id
                            }
                          >
                            <td className="incident-id">
                              INC-
                              {String(
                                incident.id
                              ).padStart(
                                4,
                                "0"
                              )}
                            </td>

                            <td>
                              {
                                incident.title
                              }
                            </td>

                            <td>
                              {incident.source ??
                                "Unknown"}
                            </td>

                            <td>
                              <span
                                className={`badge ${incident.severity.toLowerCase()}`}
                              >
                                {incident.severity.toUpperCase()}
                              </span>
                            </td>

                            <td>
                              {aiRisk ? (
                                <span
                                  className={`badge ${aiRisk}`}
                                >
                                  {aiRisk.toUpperCase()}
                                </span>
                              ) : (
                                "—"
                              )}
                            </td>

                            <td className="mono">
                              {mitre ? (
                                <>
                                  {mitre}
                                  {mitreName
                                    ? ` ${mitreName}`
                                    : ""}
                                </>
                              ) : (
                                "—"
                              )}
                            </td>

                            <td>
                              <span
                                className={`badge ${workflowClass}`}
                              >
                                {
                                  incident.workflow_status
                                }
                              </span>
                            </td>

                            <td className="mono">
                              {formatDate(
                                incident.detected_at
                              )}
                            </td>

                            <td>
                              <button
  className="view-button"
  onClick={() => setSelectedIncident(incident)}
>
  View
</button>
                              
                            </td>
                          </tr>
                        );
                      }
                    )
                  )}
                </tbody>
              </table>
            </div>
          </article>

          {/* =========================================== */}
          {/* TI / ML / MITRE */}
          {/* =========================================== */}
          {selectedIncident && (
  <article className="panel">
    <h2>
      <ShieldAlert size={18} />
      INCIDENT DETAILS — INC-
      {String(selectedIncident.id).padStart(4, "0")}
    </h2>

    <div className="data-row">
      <span>Title</span>
      <strong>{selectedIncident.title}</strong>
    </div>

    <div className="data-row">
      <span>Description</span>
      <strong>
        {selectedIncident.description ?? "N/A"}
      </strong>
    </div>

    <div className="data-row">
      <span>Severity</span>
      <strong>
        {selectedIncident.severity.toUpperCase()}
      </strong>
    </div>

    <div className="data-row">
      <span>Source</span>
      <strong>
        {selectedIncident.source ?? "N/A"}
      </strong>
    </div>

    <div className="data-row">
      <span>Source IP</span>
      <strong className="mono">
        {selectedIncident.source_ip ?? "N/A"}
      </strong>
    </div>

    <div className="data-row">
      <span>Destination IP</span>
      <strong className="mono">
        {selectedIncident.destination_ip ?? "N/A"}
      </strong>
    </div>

    <div className="data-row">
      <span>Hostname</span>
      <strong>
        {selectedIncident.hostname ?? "N/A"}
      </strong>
    </div>

    <div className="data-row">
      <span>Workflow</span>
      <strong>
        {selectedIncident.workflow_status
          .replaceAll("_", " ")
          .toUpperCase()}
      </strong>
    </div>

    <div className="data-row">
      <span>Detected</span>
      <strong>
        {formatDate(selectedIncident.detected_at)}
      </strong>
    </div>

    <div
      style={{
        display: "flex",
        justifyContent: "flex-end",
        marginTop: "14px",
      }}
    >
      <button
        className="view-button"
        onClick={() => setSelectedIncident(null)}
      >
        Close
      </button>
    </div>
  </article>
)}
          <section className="three-grid">
            {/* THREAT INTELLIGENCE */}

<article
  id="threat-intelligence"
  className="panel compact-panel"
>
  <h2>
    <Activity size={18} />
    THREAT INTELLIGENCE
  </h2>

  {threatIntelLoading ? (
                <div className="data-row">
                  <span>
                    Threat Intelligence
                  </span>

                  <strong className="yellow">
                    LOADING
                  </strong>

                  <small>
                    Enriching latest
                    incident...
                  </small>
                </div>
              ) : threatIntelError ? (
                <div className="data-row">
                  <span>
                    Threat Intelligence
                  </span>

                  <strong className="red">
                    UNAVAILABLE
                  </strong>

                  <small>
                    {threatIntelError}
                  </small>
                </div>
              ) : !primaryThreatIOC ? (
                <div className="data-row">
                  <span>
                    Threat Intelligence
                  </span>

                  <strong className="yellow">
                    NO IOC
                  </strong>

                  <small>
                    No indicator found in
                    latest incident
                  </small>
                </div>
              ) : (
                <>
                  <div className="data-row">
                    <span>
                      AbuseIPDB
                    </span>

                    <strong
                      className={providerTone(
                        abuseIPDB
                      )}
                    >
                      {providerStatus(
                        abuseIPDB
                      )}
                    </strong>

                    <small>
                      {typeof abuseIPDB?.abuse_score ===
                      "number"
                        ? `${abuseIPDB.abuse_score}% abuse · ${
                            abuseIPDB.total_reports ??
                            0
                          } reports`
                        : abuseIPDB?.reason ??
                          abuseIPDB?.error ??
                          "No score"}
                    </small>
                  </div>

                  <div className="data-row">
                    <span>
                      VirusTotal
                    </span>

                    <strong
                      className={providerTone(
                        virusTotal
                      )}
                    >
                      {providerStatus(
                        virusTotal
                      )}
                    </strong>

                    <small>
                      {typeof virusTotal?.malicious ===
                      "number"
                        ? `${virusTotal.malicious} malicious · ${
                            virusTotal.suspicious ??
                            0
                          } suspicious`
                        : virusTotal?.reason ??
                          virusTotal?.error ??
                          "No analysis"}
                    </small>
                  </div>

                  <div className="data-row">
                    <span>
                      AlienVault OTX
                    </span>

                    <strong
                      className={providerTone(
                        otx
                      )}
                    >
                      {providerStatus(otx)}
                    </strong>

                    <small>
                      {typeof otx?.pulse_count ===
                      "number"
                        ? `${otx.pulse_count} related pulses`
                        : otx?.reason ??
                          otx?.error ??
                          "No pulse data"}
                    </small>
                  </div>

                  <div className="data-row">
                    <span>MISP</span>

                    <strong
                      className={providerTone(
                        misp
                      )}
                    >
                      {providerStatus(misp)}
                    </strong>

                    <small>
                      {misp?.reason ??
                        misp?.error ??
                        (misp?.status ===
                        "not_configured"
                          ? "Optional provider not configured"
                          : `IOC: ${primaryThreatIOC.value}`)}
                    </small>
                  </div>
                </>
              )}
            </article>


            {/* MITRE */}

            {/* MACHINE LEARNING */}

<article
  id="machine-learning"
  className="panel compact-panel"
>
  <h2>
    <ChartNoAxesCombined size={18} />
    MACHINE LEARNING MODELS
  </h2>

  {!latestMLReport ? (

  
    <div
      style={{
        padding: "20px 0",
        opacity: 0.65,
        fontSize: "12px",
      }}
    >
      No ML analysis available
    </div>
  ) : (
    <>
      <div className="data-row">
        <span>Random Forest</span>

        <strong
          className={
            randomForest?.prediction === "BENIGN"
              ? "green"
              : "red"
          }
        >
          {randomForest?.prediction ?? "N/A"}
        </strong>

        <small>
          {randomForest?.prediction &&
          typeof randomForest[
            randomForest.prediction as keyof MLModelResult
          ] === "number"
            ? `${(
                Number(
                  randomForest[
                    randomForest.prediction as keyof MLModelResult
                  ]
                ) * 100
              ).toFixed(2)}% conf.`
            : "Confidence N/A"}
        </small>
      </div>

      <div className="data-row">
        <span>XGBoost</span>

        <strong
          className={
            xgboost?.prediction === "BENIGN"
              ? "green"
              : "red"
          }
        >
          {xgboost?.prediction ?? "N/A"}
        </strong>

        <small>
          {xgboost?.prediction &&
          typeof xgboost[
            xgboost.prediction as keyof MLModelResult
          ] === "number"
            ? `${(
                Number(
                  xgboost[
                    xgboost.prediction as keyof MLModelResult
                  ]
                ) * 100
              ).toFixed(2)}% conf.`
            : "Confidence N/A"}
        </small>
      </div>

      <div className="data-row">
        <span>Isolation Forest</span>

        <strong
          className={
            isolationForest?.is_anomaly
              ? "red"
              : "green"
          }
        >
          {isolationForest?.prediction ?? "N/A"}
        </strong>

        <small>
          {typeof isolationForest?.anomaly_score ===
          "number"
            ? `Score ${isolationForest.anomaly_score.toFixed(
                4
              )}`
            : "Score N/A"}
        </small>
      </div>
    </>
  )}
</article>
 
{/* MITRE */}

<article
  id="mitre-attack"
  className="panel compact-panel"
>
  <h2>
    <Radar size={18} />
    MITRE ATT&CK MAPPING
  </h2>

  {recentMitreMappings.length === 0 ? (
    <div
      style={{
        padding: "20px 0",
        opacity: 0.65,
        fontSize: "12px",
      }}
    >
      No validated MITRE mapping available
    </div>
  ) : (
    <div className="mitre-tags">
      {recentMitreMappings.map((analysis) => (
        <span key={analysis.id}>
          {analysis.mitre_technique}
          {analysis.mitre_name
            ? ` ${analysis.mitre_name}`
            : ""}
        </span>
      ))}
    </div>
  )}
</article>          
          </section>

          {/* =========================================== */}
          {/* SOAR + ASSISTANT */}
          {/* =========================================== */}

          <section className="bottom-grid">
            <article
  id="soar-actions"
  className="panel"
>
              <h2>
                <Workflow size={18} />
                SOAR PENDING ACTIONS
              </h2>

              {soarError && (
                <div
                  style={{
                    marginBottom:
                      "12px",
                    fontSize: "12px",
                  }}
                  className="red"
                >
                  {soarError}
                </div>
              )}

              {recentSoarActions.length ===
              0 ? (
                <div
                  style={{
                    padding: "20px 0",
                    opacity: 0.65,
                  }}
                >
                  No SOAR actions found.
                </div>
              ) : (
                recentSoarActions.map(
                  (action) => {
                    const status =
                      action.status.toLowerCase();

                    const waitingForApproval =
                      action.requires_approval &&
                      action.approved ===
                        null;

                    return (
                      <div
                        className="soar-row"
                        key={action.id}
                      >
                        <div>
                          <strong>
                            {formatActionType(
                              action.action_type
                            )}{" "}
                            {
                              action.target
                            }
                          </strong>

                          <span>
                            Incident INC-
                            {String(
                              action.incident_id
                            ).padStart(
                              4,
                              "0"
                            )}
                            {" · "}
                            {
                              action.status
                            }
                          </span>
                        </div>

                        {waitingForApproval ? (
                          <div className="action-buttons">
                            <button
                              className="approve"
                              disabled={
                                soarActionLoading ===
                                action.id
                              }
                              onClick={() =>
                                handleSoarDecision(
                                  action.id,
                                  "approve"
                                )
                              }
                            >
                              {soarActionLoading ===
                              action.id
                                ? "..."
                                : "Approve"}
                            </button>

                            <button
                              className="reject"
                              disabled={
                                soarActionLoading ===
                                action.id
                              }
                              onClick={() =>
                                handleSoarDecision(
                                  action.id,
                                  "reject"
                                )
                              }
                            >
                              {soarActionLoading ===
                              action.id
                                ? "..."
                                : "Reject"}
                            </button>
                          </div>
                        ) : status ===
                          "approved" ? (
                          <button
                            className="approve"
                            disabled={
                              soarActionLoading ===
                              action.id
                            }
                            onClick={() =>
                              handleSoarExecute(
                                action.id
                              )
                            }
                          >
                            {soarActionLoading ===
                            action.id
                              ? "..."
                              : "Execute"}
                          </button>
                        ) : (
                          <b
                            className={
                              status ===
                                "completed" ||
                              status ===
                                "executed" ||
                              status ===
                                "simulated"
                                ? "green"
                                : status ===
                                  "executing"
                                ? "cyan"
                                : status ===
                                    "rejected" ||
                                  status ===
                                    "execution_failed" ||
                                  status ===
                                    "blocked_by_safety"
                                ? "red"
                                : ""
                            }
                          >
                            {action.status.toUpperCase()}
                          </b>
                        )}
                      </div>
                    );
                  }
                )
              )}
            </article>

            {/* ANALYST ASSISTANT */}

            <article
  id="analyst-assistant"
  className="panel assistant-panel"
>
              <h2>
                <Bot size={18} />
                AI ANALYST ASSISTANT
              </h2>

              <div className="assistant-system">
                <strong>
                  [SYSTEM]
                </strong>

                <span>
                  Ask a cybersecurity
                  question. The assistant
                  uses the SOC knowledge
                  base and RAG context.
                </span>
              </div>

              {analystError && (
                <div className="recommendation">
                  <strong>
                    ERROR
                  </strong>

                  <p>
                    {analystError}
                  </p>
                </div>
              )}

              {analystAnswer && (
                <div className="recommendation">
                  <strong>
                    AI ANSWER
                  </strong>

                  <p>
                    {analystAnswer}
                  </p>

                  {analystSources.length >
                    0 && (
                    <div
                      style={{
                        marginTop:
                          "10px",
                        fontSize:
                          "11px",
                        opacity: 0.75,
                      }}
                    >
                      Sources:{" "}
                      {analystSources
                        .filter(
                          (item) =>
                            item.source
                        )
                        .map(
                          (item) =>
                            item.source
                        )
                        .join(", ")}
                    </div>
                  )}
                </div>
              )}

              <div className="assistant-input">
                <Terminal size={16} />

                <input
                  value={
                    analystQuestion
                  }
                  onChange={(event) =>
                    setAnalystQuestion(
                      event.target.value
                    )
                  }
                  onKeyDown={(
                    event
                  ) => {
                    if (
                      event.key ===
                        "Enter" &&
                      !analystLoading
                    ) {
                      handleAnalystAsk();
                    }
                  }}
                  placeholder="Ask AI Assistant about threats, MITRE, incidents..."
                  disabled={
                    analystLoading
                  }
                />

                <button
                  onClick={
                    handleAnalystAsk
                  }
                  disabled={
                    analystLoading
                  }
                >
                  {analystLoading
                    ? "..."
                    : "↗"}
                </button>
                            </div>
            </article>
          </section>

          {/* =========================================== */}
          {/* REPORTS */}
          {/* =========================================== */}

          <section id="reports">
            <article className="panel">
              <h2>
                <FileText size={18} />
                SOC REPORTS
              </h2>

              {recentReports.length === 0 ? (
                <div
                  style={{
                    padding: "20px 0",
                    opacity: 0.65,
                    fontSize: "12px",
                  }}
                >
                  No SOC reports available.
                </div>
              ) : (
                <div>
  {recentReports.map((report) => (
    <div className="soar-row" key={report.id}>
      <div>
        <strong>{report.title}</strong>

        <small>
          INC-{String(report.incident_id).padStart(4, "0")}
          {" · "}
          {report.mitre_technique ?? "No MITRE mapping"}
        </small>
      </div>

      <b
        className={
          report.risk_level.toLowerCase() === "critical" ||
          report.risk_level.toLowerCase() === "high"
            ? "red"
            : report.risk_level.toLowerCase() === "medium"
              ? "yellow"
              : "green"
        }
      >
        {report.risk_level.toUpperCase()}
      </b>
    </div>
  ))}
</div>
              )}
            </article>
          </section>
        {/* =========================================== */}
{/* MONITORING */}
{/* =========================================== */}

<section id="monitoring">
  <article className="panel">
    <h2>
      <Gauge size={18} />
      MONITORING
    </h2>

    <section className="metrics-grid">
      <MetricCard
        title="TOTAL INCIDENTS"
        value={String(
          metrics?.operational.total_incidents ?? 0
        )}
      />

      <MetricCard
        title="INCIDENTS WITH MTTD"
        value={String(
          metrics?.operational.incidents_with_mttd ?? 0
        )}
        tone="cyan"
      />

      <MetricCard
        title="INCIDENTS WITH MTTR"
        value={String(
          metrics?.operational.incidents_with_mttr ?? 0
        )}
        tone="cyan"
      />

      <MetricCard
        title="AVERAGE MTTD"
        value={formatDuration(
          metrics?.operational.average_mttd_seconds
        )}
        tone="cyan"
      />

      <MetricCard
        title="AVERAGE MTTR"
        value={formatDuration(
          metrics?.operational.average_mttr_seconds
        )}
        tone="cyan"
      />

      <MetricCard
        title="REVIEWED INCIDENTS"
        value={String(
          metrics?.quality.reviewed_incidents ?? 0
        )}
      />

      <MetricCard
        title="TRUE POSITIVES"
        value={String(
          metrics?.quality.true_positive_count ?? 0
        )}
        tone="green"
      />

      <MetricCard
        title="FALSE POSITIVES"
        value={String(
          metrics?.quality.false_positive_count ?? 0
        )}
        tone="red"
      />

      <MetricCard
        title="FALSE POSITIVE RATE"
        value={
          metrics?.quality.false_positive_rate != null
            ? `${metrics.quality.false_positive_rate.toFixed(2)}%`
            : "N/A"
        }
        tone="yellow"
      />
    </section>
  </article>
</section>
        </div>
      </section>
    </main>
  );
}