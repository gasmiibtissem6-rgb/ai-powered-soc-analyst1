"use client";

import {
  useEffect,
  useState,
} from "react";

import {
  useParams,
  useRouter,
} from "next/navigation";

import {
  apiRequest,
} from "@/lib/api";

import {
  initKeycloak,
} from "@/lib/keycloak-auth";


type Incident = {
  id: number;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  source: string | null;

  hostname?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;

  workflow_status?: string;
  workflow_error?: string | null;
  workflow_thread_id?: string | null;

  correlation_id?: string | null;
};


type AIAnalysis = {
  id?: number;
  incident_id?: number;

  summary: string;
  risk_level: string;

  explanation?: string | null;
  recommendation?: string | null;

  mitre_technique?: string | null;
  mitre_name?: string | null;
  mitre_valid?: boolean;

  model_used?: string | null;
};


type SOCReport = {
  id: number;

  incident_id: number;
  ai_analysis_id?: number | null;
  thread_id?: string | null;

  title: string;
  summary: string;
  risk_level: string;

  ml_status?: string | null;
  ml_prediction?: string | null;

  ml_probabilities?: Record<
    string,
    unknown
  > | null;

  ml_engine?: string | null;
  ml_is_anomaly?: boolean | null;
  ml_anomaly_score?: number | null;

  mitre_technique?: string | null;
  mitre_name?: string | null;

  recommendation?: string | null;
  response_status?: string | null;

  human_review_status?: string | null;
  human_comment?: string | null;

  rag_sources?: string[] | null;
  agent_trace?: string[] | null;

  created_at: string;
};


type ThreatIntel = {
  incident_id: number;

  source: string;

  source_ip?: string | null;
  destination_ip?: string | null;

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

  threat_intelligence: unknown[];
};


type CorrelationIncident = {
  id: number;
  title: string;
  description?: string | null;
  severity: string;
  status: string;
  source?: string | null;
  hostname?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;
  assigned_to?: string | null;
  workflow_status?: string | null;
  workflow_error?: string | null;
  correlation_id?: string | null;
  created_at: string;
};


type CorrelationGroup = {
  correlation_id: string;
  incident_count: number;
  sources: string[];
  source_ips: string[];
  destination_ips: string[];
  highest_severity: string;
  first_seen: string;
  last_seen: string;
  incidents: CorrelationIncident[];
};


type GenerateAIAnalysisResponse = {
  incident: {
    id: number;
    title: string;
    description: string;
    severity: string;
    status: string;
    source: string;
  };

  threat_intelligence: unknown[];

  analysis: AIAnalysis;

  mitre_validation: {
    technique_id?: string | null;
    name?: string | null;
    description?: string | null;
    valid?: boolean;
    error?: string;
  };
};


type AgentWorkflowResponse = {
  status:
    | "waiting_for_human"
    | "completed";

  thread_id: string;

  ai_analysis_id?: number;
  soc_report_id?: number;
  soar_action_id?: number | null;

  interrupt?: unknown[];

  incident?: Record<
    string,
    unknown
  >;

  correlated_incidents?: unknown[];

  triage?: Record<
    string,
    unknown
  > | null;

  ml_analysis?: Record<
    string,
    unknown
  > | null;

  threat_intelligence?: unknown;

  rag_context?: unknown[];

  investigation?: {
    summary?: string;
    risk_level?: string;
    explanation?: string;
    recommendation?: string;
    mitre_technique?: string;
  } | null;

  mitre_validation?: {
    technique_id?: string | null;
    name?: string | null;
    description?: string | null;
    valid?: boolean;
  } | null;

  human_review?: {
    required?: boolean;
    approved?: boolean | null;
    status?: string | null;
    comment?: string | null;
  } | null;

  response?: Record<
    string,
    unknown
  > | null;

  soar_action?: {
    action_type?: string;
    target?: string;
    status?: string;
    requires_approval?: boolean;
  } | null;

  report?: Record<
    string,
    unknown
  > | null;

  agent_trace?: string[];
};


export default function IncidentDetailsPage() {
  const params =
    useParams();

  const router =
    useRouter();

  const id =
    params.id as string;


  const [
    incident,
    setIncident,
  ] =
    useState<Incident | null>(
      null
    );


  const [
    analysis,
    setAnalysis,
  ] =
    useState<AIAnalysis[]>(
      []
    );


  const [
    aiAnalysis,
    setAiAnalysis,
  ] =
    useState<AIAnalysis | null>(
      null
    );


  const [
    threatIntel,
    setThreatIntel,
  ] =
    useState<ThreatIntel | null>(
      null
    );


  const [
    reports,
    setReports,
  ] =
    useState<SOCReport[]>(
      []
    );


  const [
    correlationGroup,
    setCorrelationGroup,
  ] =
    useState<CorrelationGroup | null>(
      null
    );


  const [
    loading,
    setLoading,
  ] =
    useState(
      true
    );


  const [
    aiLoading,
    setAiLoading,
  ] =
    useState(
      false
    );


  const [
    aiError,
    setAiError,
  ] =
    useState<string | null>(
      null
    );


  const [
    workflowLoading,
    setWorkflowLoading,
  ] =
    useState(
      false
    );


  const [
    workflowError,
    setWorkflowError,
  ] =
    useState<string | null>(
      null
    );


  const [
    workflowResult,
    setWorkflowResult,
  ] =
    useState<
      AgentWorkflowResponse | null
    >(
      null
    );


  const [
    workflowThreadId,
    setWorkflowThreadId,
  ] =
    useState<string | null>(
      null
    );


  const [
    workflowStatus,
    setWorkflowStatus,
  ] =
    useState<string | null>(
      null
    );


  const [
    humanComment,
    setHumanComment,
  ] =
    useState("");


  const [
    resumeLoading,
    setResumeLoading,
  ] =
    useState(
      false
    );


  // =====================================================
  // REFRESH AI ANALYSIS
  // =====================================================

  async function refreshAIAnalysis() {
    const analysisData =
      await apiRequest<
        AIAnalysis[]
      >(
        `/ai-analysis/incident/${id}`
      );

    setAnalysis(
      analysisData
    );

    setAiAnalysis(
      analysisData.length > 0
        ? analysisData[0]
        : null
    );
  }


  // =====================================================
  // REFRESH SOC REPORTS
  // =====================================================

  async function refreshReports() {
    try {
      const reportsData =
        await apiRequest<
          SOCReport[]
        >(
          `/reports/incident/${id}`
        );

      setReports(
        reportsData
      );

    } catch (
      error
    ) {
      console.log(
        "Unable to refresh SOC reports",
        error
      );
    }
  }


  // =====================================================
  // RUN AI ANALYSIS
  // =====================================================

  async function runAIInvestigation() {
    try {
      setAiLoading(
        true
      );

      setAiError(
        null
      );


      const result =
        await apiRequest<
          GenerateAIAnalysisResponse
        >(
          `/ai-analysis/generate/${id}`,
          {
            method:
              "POST",
          }
        );


      setAiAnalysis(
        result.analysis
      );


      setAnalysis(
        (previous) => [
          result.analysis,
          ...previous.filter(
            (item) =>
              item.id !==
              result.analysis.id
          ),
        ]
      );

    } catch (
      error
    ) {
      console.error(
        "AI Investigation failed:",
        error
      );


      setAiError(
        error instanceof Error
          ? error.message
          : "AI Investigation failed"
      );

    } finally {
      setAiLoading(
        false
      );
    }
  }


  // =====================================================
  // RUN FULL SOC WORKFLOW
  // =====================================================

  async function runFullSOCWorkflow() {
    try {
      setWorkflowLoading(
        true
      );

      setWorkflowError(
        null
      );


      const result =
        await apiRequest<
          AgentWorkflowResponse
        >(
          `/agents/analyze/${id}`,
          {
            method:
              "POST",
          }
        );


      setWorkflowResult(
        result
      );


      setWorkflowStatus(
        result.status
      );


      setWorkflowThreadId(
        result.thread_id
      );


      setIncident(
        (current) =>
          current
            ? {
                ...current,
                workflow_status:
                  result.status,
                workflow_thread_id:
                  result.thread_id,
                workflow_error:
                  null,
              }
            : current
      );


      if (
        result.status ===
        "completed"
      ) {
        await refreshAIAnalysis();
      }


      await refreshReports();

    } catch (
      error
    ) {
      console.error(
        "SOC workflow failed:",
        error
      );


      setWorkflowError(
        error instanceof Error
          ? error.message
          : "SOC workflow failed"
      );

    } finally {
      setWorkflowLoading(
        false
      );
    }
  }


  // =====================================================
  // RESUME SOC WORKFLOW
  // =====================================================

  async function resumeSOCWorkflow(
    approved: boolean
  ) {
    if (
      !workflowThreadId
    ) {
      setWorkflowError(
        "Missing workflow thread ID"
      );

      return;
    }


    try {
      setResumeLoading(
        true
      );

      setWorkflowError(
        null
      );


      const result =
        await apiRequest<
          AgentWorkflowResponse
        >(
          `/agents/resume/${workflowThreadId}`,
          {
            method:
              "POST",

            body:
              JSON.stringify({
                approved,

                comment:
                  humanComment.trim()
                  ||
                  (
                    approved
                      ? "Approved from SOC frontend"
                      : "Rejected from SOC frontend"
                  ),
              }),
          }
        );


      setWorkflowResult(
        result
      );


      setWorkflowStatus(
        result.status
      );


      setWorkflowThreadId(
        result.thread_id
        ??
        workflowThreadId
      );


      setIncident(
        (current) =>
          current
            ? {
                ...current,

                workflow_status:
                  result.status,

                workflow_thread_id:
                  result.thread_id
                  ??
                  workflowThreadId,

                workflow_error:
                  null,
              }
            : current
      );


      if (
        result.status ===
        "completed"
      ) {
        await Promise.all([
          refreshAIAnalysis(),
          refreshReports(),
        ]);
      }

    } catch (
      error
    ) {
      console.error(
        "SOC workflow resume failed:",
        error
      );


      setWorkflowError(
        error instanceof Error
          ? error.message
          : "Unable to resume SOC workflow"
      );

    } finally {
      setResumeLoading(
        false
      );
    }
  }


  // =====================================================
  // LOAD INCIDENT DATA
  // =====================================================

  useEffect(() => {
    let active =
      true;


    async function load() {
      try {
        const authenticated =
          await initKeycloak();


        if (
          !active
        ) {
          return;
        }


        if (
          !authenticated
        ) {
          router.replace(
            "/login"
          );

          return;
        }


        const incidentData =
          await apiRequest<
            Incident
          >(
            `/incidents/${id}`
          );


        const analysisData =
          await apiRequest<
            AIAnalysis[]
          >(
            `/ai-analysis/incident/${id}`
          );


        let reportsData:
          SOCReport[] = [];


        try {
          reportsData =
            await apiRequest<
              SOCReport[]
            >(
              `/reports/incident/${id}`
            );

        } catch (
          error
        ) {
          console.log(
            "No SOC reports available",
            error
          );
        }


        let threatData:
          ThreatIntel | null =
            null;


        try {
          threatData =
            await apiRequest<
              ThreatIntel
            >(
              `/threat-intelligence/incident/${id}`
            );

        } catch (
          error
        ) {
          console.log(
            "No threat intelligence data",
            error
          );
        }


        let correlationData:
          CorrelationGroup | null =
            null;


        if (
          incidentData.correlation_id
        ) {
          try {
            correlationData =
              await apiRequest<
                CorrelationGroup
              >(
                `/incidents/correlation/${encodeURIComponent(
                  incidentData.correlation_id
                )}`
              );

          } catch (
            error
          ) {
            console.log(
              "No correlation group available",
              error
            );
          }
        }


        if (
          !active
        ) {
          return;
        }


        // IMPORTANT:
        // Restore the incident object itself.
        setIncident(
          incidentData
        );


        // Restore workflow state after refresh/navigation.
        setWorkflowStatus(
          incidentData.workflow_status
          ?? null
        );


        setWorkflowThreadId(
          incidentData.workflow_thread_id
          ?? null
        );


        /*
         * A workflow started automatically by Wazuh or
         * Suricata may already be waiting for human review
         * when this page is opened.
         *
         * The original workflowResult lives only in React
         * memory, so reconstruct the minimum required state
         * from the persisted incident fields.
         */
        if (
          incidentData.workflow_thread_id
          &&
          (
            incidentData.workflow_status ===
              "waiting_for_human"
            ||
            incidentData.workflow_status ===
              "completed"
          )
        ) {
          setWorkflowResult({
            status:
              incidentData.workflow_status,

            thread_id:
              incidentData.workflow_thread_id,
          });
        }


        setWorkflowError(
          incidentData.workflow_error
          ?? null
        );


        setAnalysis(
          analysisData
        );


        setAiAnalysis(
          analysisData.length > 0
            ? analysisData[0]
            : null
        );


        setThreatIntel(
          threatData
        );


        setCorrelationGroup(
          correlationData
        );


        setReports(
          reportsData
        );

      } catch (
        error
      ) {
        console.error(
          "Unable to load incident:",
          error
        );

      } finally {
        if (
          active
        ) {
          setLoading(
            false
          );
        }
      }
    }


    void load();


    return () => {
      active =
        false;
    };

  }, [
    id,
    router,
  ]);


  // =====================================================
  // LATEST ANALYSIS
  // =====================================================

  const latestAnalysis =
    analysis.length > 0
      ? analysis[0]
      : null;


  // =====================================================
  // LOADING
  // =====================================================

  if (
    loading
  ) {
    return (
      <div className="p-10">
        Loading incident...
      </div>
    );
  }


  // =====================================================
  // INCIDENT NOT FOUND
  // =====================================================

  if (
    !incident
  ) {
    return (
      <div className="p-10">
        Incident not found
      </div>
    );
  }


  // =====================================================
  // UI
  // =====================================================

  return (
    <main className="p-8 space-y-6">

      {/* =================================================
          SOC AI INVESTIGATION
      ================================================= */}

      <section className="rounded-xl border p-6">

        <h2 className="text-xl font-bold">
          SOC AI Investigation
        </h2>


        <button
          type="button"
          onClick={
            () =>
              void runAIInvestigation()
          }
          disabled={
            aiLoading
          }
          className="
            mt-4
            rounded-lg
            bg-blue-600
            px-5
            py-2
            text-white
            disabled:cursor-not-allowed
            disabled:opacity-50
          "
        >
          {
            aiLoading
              ? "Running AI Investigation..."
              : "Run AI Investigation"
          }
        </button>


        {
          aiError && (
            <p className="mt-4 text-red-400">
              {aiError}
            </p>
          )
        }


        {
          aiAnalysis && (
            <div className="mt-5 rounded-lg border p-4">

              <h3 className="font-semibold">
                AI Investigation completed
              </h3>


              <p className="mt-3">
                Incident ID:

                <b className="ml-2">
                  {
                    aiAnalysis.incident_id
                    ?? incident.id
                  }
                </b>
              </p>


              <p className="mt-2">
                Risk:

                <b className="ml-2">
                  {
                    aiAnalysis.risk_level
                  }
                </b>
              </p>


              {
                aiAnalysis.mitre_technique && (
                  <p className="mt-2">
                    MITRE:

                    <b className="ml-2">
                      {
                        aiAnalysis.mitre_technique
                      }

                      {
                        aiAnalysis.mitre_name
                          ? ` - ${aiAnalysis.mitre_name}`
                          : ""
                      }
                    </b>
                  </p>
                )
              }


              {
                aiAnalysis.model_used && (
                  <p className="mt-2">
                    Model:

                    <b className="ml-2">
                      {
                        aiAnalysis.model_used
                      }
                    </b>
                  </p>
                )
              }

            </div>
          )
        }

      </section>


      {/* =================================================
          FULL SOC AGENT WORKFLOW
      ================================================= */}

      <section className="rounded-xl border p-6">

        <h2 className="text-xl font-bold">
          Full SOC Agent Workflow
        </h2>


        <p className="mt-2 text-sm opacity-80">
          Run the complete LangGraph SOC workflow including
          triage, machine learning, threat intelligence,
          investigation, MITRE ATT&CK, human review,
          response and SOAR.
        </p>


        <button
          type="button"
          onClick={
            () =>
              void runFullSOCWorkflow()
          }
          disabled={
            workflowLoading
            ||
            resumeLoading
            ||
            workflowStatus ===
              "waiting_for_human"
          }
          className="
            mt-4
            rounded-lg
            bg-purple-600
            px-5
            py-2
            text-white
            disabled:cursor-not-allowed
            disabled:opacity-50
          "
        >
          {
            workflowLoading
              ? "Running SOC Workflow..."
              : workflowStatus ===
                  "waiting_for_human"
                ? "Waiting for Human Approval"
                : "Run Full SOC Workflow"
          }
        </button>


        {
          workflowError && (
            <p className="mt-4 text-red-400">
              {workflowError}
            </p>
          )
        }


        {
          (
            workflowStatus
            ||
            workflowThreadId
            ||
            workflowResult
          ) && (
            <div className="mt-5 rounded-lg border p-4">

              {
                workflowStatus && (
                  <p>
                    <b>Status:</b>

                    <span className="ml-2">
                      {
                        workflowStatus
                      }
                    </span>
                  </p>
                )
              }


              {
                workflowThreadId && (
                  <p className="mt-2 break-all">
                    <b>Thread ID:</b>

                    <span className="ml-2">
                      {
                        workflowThreadId
                      }
                    </span>
                  </p>
                )
              }


              {
                workflowResult
                  ?.investigation && (
                  <div className="mt-4">

                    <h3 className="font-semibold">
                      Investigation
                    </h3>


                    {
                      workflowResult
                        .investigation
                        .risk_level && (
                        <p className="mt-2">
                          Risk:

                          <b className="ml-2">
                            {
                              workflowResult
                                .investigation
                                .risk_level
                            }
                          </b>
                        </p>
                      )
                    }


                    {
                      workflowResult
                        .investigation
                        .summary && (
                        <p
                          className="
                            mt-2
                            whitespace-pre-wrap
                          "
                        >
                          {
                            workflowResult
                              .investigation
                              .summary
                          }
                        </p>
                      )
                    }

                  </div>
                )
              }


              {
                workflowResult
                  ?.mitre_validation && (
                  <div className="mt-4">

                    <h3 className="font-semibold">
                      MITRE ATT&CK
                    </h3>


                    <p className="mt-2">
                      {
                        workflowResult
                          .mitre_validation
                          .technique_id
                      }

                      {
                        workflowResult
                          .mitre_validation
                          .name
                          ? ` - ${
                              workflowResult
                                .mitre_validation
                                .name
                            }`
                          : ""
                      }
                    </p>

                  </div>
                )
              }


              {
                Array.isArray(
                  workflowResult
                    ?.agent_trace
                )
                &&
                (
                  workflowResult
                    ?.agent_trace
                    ?.length
                  ?? 0
                ) > 0
                && (
                  <div className="mt-4">

                    <h3 className="font-semibold">
                      Agent Trace
                    </h3>


                    <ul className="mt-2 ml-6 list-disc">
                      {
                        workflowResult
                          ?.agent_trace
                          ?.map(
                            (
                              agent,
                              index
                            ) => (
                              <li
                                key={
                                  `${agent}-${index}`
                                }
                              >
                                {
                                  agent
                                }
                              </li>
                            )
                          )
                      }
                    </ul>

                  </div>
                )
              }


              {/* =========================================
                  HUMAN APPROVAL
              ========================================= */}

              {
                workflowStatus ===
                  "waiting_for_human"
                &&
                workflowThreadId && (
                  <div className="mt-6 rounded-lg border p-4">

                    <h3 className="font-semibold">
                      Human Approval Required
                    </h3>


                    {
                      Array.isArray(
                        workflowResult
                          ?.interrupt
                      )
                      &&
                      (
                        workflowResult
                          ?.interrupt
                          ?.length
                        ?? 0
                      ) > 0 && (
                        <pre
                          className="
                            mt-3
                            whitespace-pre-wrap
                            break-words
                            text-sm
                          "
                        >
                          {
                            JSON.stringify(
                              workflowResult
                                ?.interrupt,
                              null,
                              2
                            )
                          }
                        </pre>
                      )
                    }


                    <textarea
                      value={
                        humanComment
                      }
                      onChange={
                        (event) =>
                          setHumanComment(
                            event.target.value
                          )
                      }
                      placeholder="Human review comment..."
                      className="
                        mt-4
                        w-full
                        rounded-lg
                        border
                        bg-transparent
                        p-3
                      "
                    />


                    <div className="mt-4 flex gap-3">

                      <button
                        type="button"
                        onClick={
                          () =>
                            void resumeSOCWorkflow(
                              true
                            )
                        }
                        disabled={
                          resumeLoading
                        }
                        className="
                          rounded-lg
                          bg-green-600
                          px-4
                          py-2
                          text-white
                          disabled:opacity-50
                        "
                      >
                        {
                          resumeLoading
                            ? "Processing..."
                            : "Approve"
                        }
                      </button>


                      <button
                        type="button"
                        onClick={
                          () =>
                            void resumeSOCWorkflow(
                              false
                            )
                        }
                        disabled={
                          resumeLoading
                        }
                        className="
                          rounded-lg
                          bg-red-600
                          px-4
                          py-2
                          text-white
                          disabled:opacity-50
                        "
                      >
                        Reject
                      </button>

                    </div>

                  </div>
                )
              }


              {/* =========================================
                  COMPLETED
              ========================================= */}

              {
                workflowStatus ===
                  "completed" && (
                  <div className="mt-5">

                    <p
                      className="
                        font-semibold
                        text-green-400
                      "
                    >
                      SOC workflow completed
                    </p>


                    {
                      workflowResult
                        ?.ai_analysis_id && (
                        <p className="mt-2">
                          AI Analysis ID:

                          <b className="ml-2">
                            {
                              workflowResult
                                .ai_analysis_id
                            }
                          </b>
                        </p>
                      )
                    }


                    {
                      workflowResult
                        ?.soc_report_id && (
                        <p>
                          SOC Report ID:

                          <b className="ml-2">
                            {
                              workflowResult
                                .soc_report_id
                            }
                          </b>
                        </p>
                      )
                    }


                    {
                      workflowResult
                        ?.soar_action_id && (
                        <p>
                          SOAR Action ID:

                          <b className="ml-2">
                            {
                              workflowResult
                                .soar_action_id
                            }
                          </b>
                        </p>
                      )
                    }

                  </div>
                )
              }

            </div>
          )
        }

      </section>


      {/* =================================================
          INCIDENT DETAILS
      ================================================= */}

      <section className="rounded-xl border p-6">

        <h1 className="text-2xl font-bold">
          Incident #{incident.id}
        </h1>


        <h2 className="mt-3 text-xl">
          {
            incident.title
          }
        </h2>


        <p className="mt-4 whitespace-pre-wrap break-words">
          {
            incident.description
            || "No description"
          }
        </p>


        <div
          className="
            mt-6
            grid
            grid-cols-1
            gap-4
            md:grid-cols-3
          "
        >
          <div>
            Severity:

            <b className="ml-2">
              {
                incident.severity
              }
            </b>
          </div>


          <div>
            Status:

            <b className="ml-2">
              {
                incident.status
              }
            </b>
          </div>


          <div>
            Source:

            <b className="ml-2">
              {
                incident.source
                || "—"
              }
            </b>
          </div>
        </div>


        {
          (
            incident.hostname
            ||
            incident.source_ip
            ||
            incident.destination_ip
            ||
            incident.username
          ) && (
            <div
              className="
                mt-6
                grid
                grid-cols-1
                gap-4
                md:grid-cols-2
              "
            >

              {
                incident.hostname && (
                  <div>
                    Hostname:

                    <b className="ml-2">
                      {
                        incident.hostname
                      }
                    </b>
                  </div>
                )
              }


              {
                incident.source_ip && (
                  <div>
                    Source IP:

                    <b className="ml-2">
                      {
                        incident.source_ip
                      }
                    </b>
                  </div>
                )
              }


              {
                incident.destination_ip && (
                  <div>
                    Destination IP:

                    <b className="ml-2">
                      {
                        incident.destination_ip
                      }
                    </b>
                  </div>
                )
              }


              {
                incident.username && (
                  <div>
                    Username:

                    <b className="ml-2">
                      {
                        incident.username
                      }
                    </b>
                  </div>
                )
              }

            </div>
          )
        }

      </section>


      {/* =================================================
          CORRELATION
      ================================================= */}

      {
        correlationGroup && (
          <section className="rounded-xl border p-6">

            <div
              className="
                flex
                flex-col
                gap-3
                md:flex-row
                md:items-start
                md:justify-between
              "
            >
              <div>
                <h2 className="text-xl font-bold">
                  Correlation
                </h2>

                <p className="mt-1 text-sm text-slate-400">
                  Multi-source incident correlation group.
                </p>
              </div>

              <span
                className="
                  w-fit
                  rounded-full
                  border
                  border-cyan-500/40
                  bg-cyan-500/10
                  px-3
                  py-1
                  text-xs
                  font-medium
                  text-cyan-300
                "
              >
                {
                  correlationGroup.incident_count
                }{" "}
                incident
                {
                  correlationGroup.incident_count === 1
                    ? ""
                    : "s"
                }
              </span>
            </div>


            <div
              className="
                mt-5
                grid
                gap-4
                md:grid-cols-2
                xl:grid-cols-4
              "
            >
              <div>
                <p className="text-xs uppercase text-slate-500">
                  Correlation ID
                </p>

                <p className="mt-1 break-all font-mono text-sm">
                  {
                    correlationGroup.correlation_id
                  }
                </p>
              </div>


              <div>
                <p className="text-xs uppercase text-slate-500">
                  Sources
                </p>

                <p className="mt-1 text-sm">
                  {
                    correlationGroup.sources.length > 0
                      ? correlationGroup.sources.join(", ")
                      : "—"
                  }
                </p>
              </div>


              <div>
                <p className="text-xs uppercase text-slate-500">
                  Highest Severity
                </p>

                <p className="mt-1 text-sm">
                  {
                    correlationGroup.highest_severity
                  }
                </p>
              </div>


              <div>
                <p className="text-xs uppercase text-slate-500">
                  Time Window
                </p>

                <p className="mt-1 text-sm">
                  {
                    new Date(
                      correlationGroup.first_seen
                    ).toLocaleString()
                  }
                  {" → "}
                  {
                    new Date(
                      correlationGroup.last_seen
                    ).toLocaleString()
                  }
                </p>
              </div>
            </div>


            <div className="mt-6 space-y-3">

              <h3 className="font-semibold">
                Correlated Incidents
              </h3>

              {
                correlationGroup.incidents.map(
                  (item) => (
                    <button
                      key={
                        item.id
                      }
                      type="button"
                      onClick={
                        () =>
                          router.push(
                            `/incidents/${item.id}`
                          )
                      }
                      className="
                        block
                        w-full
                        rounded-lg
                        border
                        border-slate-700
                        p-4
                        text-left
                        hover:bg-slate-800/40
                      "
                    >
                      <div
                        className="
                          flex
                          flex-col
                          gap-2
                          md:flex-row
                          md:items-center
                          md:justify-between
                        "
                      >
                        <div>
                          <p className="font-semibold text-cyan-300">
                            Incident #
                            {
                              item.id
                            }{" "}
                            ·{" "}
                            {
                              item.source || "Unknown source"
                            }
                          </p>

                          <p className="mt-1 text-sm text-slate-300">
                            {
                              item.title
                            }
                          </p>
                        </div>

                        <div className="text-sm text-slate-400">
                          Severity:{" "}
                          <strong className="text-slate-200">
                            {
                              item.severity
                            }
                          </strong>
                        </div>
                      </div>

                      <div
                        className="
                          mt-3
                          grid
                          gap-2
                          text-xs
                          text-slate-500
                          md:grid-cols-3
                        "
                      >
                        <span>
                          Source IP:{" "}
                          {
                            item.source_ip || "—"
                          }
                        </span>

                        <span>
                          Destination IP:{" "}
                          {
                            item.destination_ip || "—"
                          }
                        </span>

                        <span>
                          Workflow:{" "}
                          {
                            item.workflow_status || "—"
                          }
                        </span>
                      </div>
                    </button>
                  )
                )
              }

            </div>

          </section>
        )
      }


      {/* =================================================
          SOC REPORTS
      ================================================= */}

      <section className="rounded-xl border p-6">

        <div
          className="
            flex
            flex-col
            gap-4
            md:flex-row
            md:items-center
            md:justify-between
          "
        >
          <div>

            <h2 className="text-xl font-bold">
              SOC Reports
            </h2>


            <p className="mt-1 text-sm text-slate-400">
              Reports generated for this incident
              by the SOC workflow.
            </p>

          </div>


          <button
            type="button"
            onClick={
              () =>
                router.push(
                  "/reports"
                )
            }
            className="
              rounded-lg
              border
              border-slate-600
              px-4
              py-2
              text-sm
              hover:bg-slate-800
            "
          >
            View All Reports
          </button>

        </div>


        {
          reports.length > 0 ? (
            <div className="mt-5 space-y-4">

              {
                reports.map(
                  (report) => (
                    <article
                      key={
                        report.id
                      }
                      className="
                        rounded-xl
                        border
                        border-slate-700
                        bg-slate-900/20
                        p-5
                      "
                    >

                      <div
                        className="
                          flex
                          flex-col
                          gap-3
                          md:flex-row
                          md:items-start
                          md:justify-between
                        "
                      >

                        <div>

                          <p className="text-sm text-cyan-300">
                            Report #
                            {
                              report.id
                            }
                          </p>


                          <h3 className="mt-1 text-lg font-semibold">
                            {
                              report.title
                            }
                          </h3>

                        </div>


                        <span
                          className="
                            w-fit
                            rounded-full
                            border
                            border-slate-600
                            px-3
                            py-1
                            text-xs
                          "
                        >
                          Risk:{" "}
                          {
                            report.risk_level
                          }
                        </span>

                      </div>


                      <p
                        className="
                          mt-4
                          text-sm
                          leading-6
                          text-slate-300
                        "
                      >
                        {
                          report.summary
                        }
                      </p>


                      {
                        report.recommendation && (
                          <div
                            className="
                              mt-4
                              rounded-lg
                              border
                              border-cyan-500/20
                              bg-cyan-500/5
                              p-4
                            "
                          >

                            <p
                              className="
                                text-xs
                                uppercase
                                tracking-wider
                                text-cyan-300
                              "
                            >
                              Recommendation
                            </p>


                            <p className="mt-2 text-sm leading-6">
                              {
                                report.recommendation
                              }
                            </p>

                          </div>
                        )
                      }


                      <div
                        className="
                          mt-4
                          grid
                          gap-3
                          text-sm
                          md:grid-cols-2
                          xl:grid-cols-4
                        "
                      >

                        <div>
                          <span className="text-slate-500">
                            MITRE:
                          </span>{" "}

                          {
                            report.mitre_technique
                            || "—"
                          }
                        </div>


                        <div>
                          <span className="text-slate-500">
                            ML:
                          </span>{" "}

                          {
                            report.ml_prediction
                            ||
                            report.ml_status
                            ||
                            "—"
                          }
                        </div>


                        <div>
                          <span className="text-slate-500">
                            Human Review:
                          </span>{" "}

                          {
                            report.human_review_status
                            || "—"
                          }
                        </div>


                        <div>
                          <span className="text-slate-500">
                            Response:
                          </span>{" "}

                          {
                            report.response_status
                            || "—"
                          }
                        </div>

                      </div>


                      <p className="mt-4 text-xs text-slate-500">
                        Created:{" "}

                        {
                          new Date(
                            report.created_at
                          ).toLocaleString()
                        }
                      </p>

                    </article>
                  )
                )
              }

            </div>
          ) : (
            <p className="mt-5 text-sm text-slate-500">
              No SOC report has been generated
              for this incident yet.
            </p>
          )
        }

      </section>


      {/* =================================================
          AI ANALYSIS
      ================================================= */}

      <section className="rounded-xl border p-6">

        <h2 className="text-xl font-bold">
          AI Analysis
        </h2>


        {
          !latestAnalysis ? (
            <p className="mt-4">
              No AI analysis available
            </p>
          ) : (
            <div className="mt-4 rounded-lg border p-4">

              <p>
                <b>
                  Risk:
                </b>

                <span className="ml-2">
                  {
                    latestAnalysis
                      .risk_level
                  }
                </span>
              </p>


              <div className="mt-4">

                <p className="font-semibold">
                  Summary
                </p>


                <p className="mt-1 whitespace-pre-wrap">
                  {
                    latestAnalysis
                      .summary
                  }
                </p>

              </div>


              {
                latestAnalysis
                  .explanation && (
                  <div className="mt-4">

                    <p className="font-semibold">
                      Explanation
                    </p>


                    <p className="mt-1 whitespace-pre-wrap">
                      {
                        latestAnalysis
                          .explanation
                      }
                    </p>

                  </div>
                )
              }


              {
                latestAnalysis
                  .recommendation && (
                  <div className="mt-4">

                    <p className="font-semibold">
                      Recommendation
                    </p>


                    <p className="mt-1 whitespace-pre-line">
                      {
                        latestAnalysis
                          .recommendation
                      }
                    </p>

                  </div>
                )
              }


              {
                latestAnalysis
                  .mitre_technique && (
                  <p className="mt-4">

                    <b>
                      MITRE:
                    </b>


                    <span className="ml-2">
                      {
                        latestAnalysis
                          .mitre_technique
                      }

                      {
                        latestAnalysis
                          .mitre_name
                          ? ` - ${latestAnalysis.mitre_name}`
                          : ""
                      }
                    </span>

                  </p>
                )
              }


              {
                typeof latestAnalysis
                  .mitre_valid ===
                  "boolean" && (
                  <p className="mt-2">

                    <b>
                      MITRE Validation:
                    </b>


                    <span className="ml-2">
                      {
                        latestAnalysis
                          .mitre_valid
                          ? "Valid"
                          : "Invalid"
                      }
                    </span>

                  </p>
                )
              }


              {
                latestAnalysis
                  .model_used && (
                  <p className="mt-2">

                    <b>
                      Model:
                    </b>


                    <span className="ml-2">
                      {
                        latestAnalysis
                          .model_used
                      }
                    </span>

                  </p>
                )
              }

            </div>
          )
        }

      </section>


      {/* =================================================
          THREAT INTELLIGENCE
      ================================================= */}

      <section className="rounded-xl border p-6">

        <h2 className="text-xl font-bold">
          Threat Intelligence
        </h2>


        {
          !threatIntel ? (
            <p className="mt-4">
              No threat intelligence data
            </p>
          ) : (
            <div className="mt-4 space-y-5">

              {/* IOC SUMMARY */}

              <div>

                <h3 className="font-semibold">
                  IOC Summary
                </h3>


                <p>
                  IPs:

                  <b className="ml-2">
                    {
                      threatIntel
                        .ioc_summary
                        .ips
                    }
                  </b>
                </p>


                <p>
                  Domains:

                  <b className="ml-2">
                    {
                      threatIntel
                        .ioc_summary
                        .domains
                    }
                  </b>
                </p>


                <p>
                  URLs:

                  <b className="ml-2">
                    {
                      threatIntel
                        .ioc_summary
                        .urls
                    }
                  </b>
                </p>


                <p>
                  Hashes:

                  <b className="ml-2">
                    {
                      threatIntel
                        .ioc_summary
                        .hashes
                    }
                  </b>
                </p>

              </div>


              {/* EXTRACTED INDICATORS */}

              <div>

                <h3 className="font-semibold">
                  Extracted Indicators
                </h3>


                {
                  threatIntel
                    .extracted_iocs
                    .ips
                    .length > 0 && (
                    <p className="mt-2">

                      IPs:

                      <span className="ml-2">
                        {
                          threatIntel
                            .extracted_iocs
                            .ips
                            .join(", ")
                        }
                      </span>

                    </p>
                  )
                }


                {
                  threatIntel
                    .extracted_iocs
                    .domains
                    .length > 0 && (
                    <p className="mt-2">

                      Domains:

                      <span className="ml-2">
                        {
                          threatIntel
                            .extracted_iocs
                            .domains
                            .join(", ")
                        }
                      </span>

                    </p>
                  )
                }


                {
                  threatIntel
                    .extracted_iocs
                    .urls
                    .length > 0 && (
                    <p className="mt-2">

                      URLs:

                      <span className="ml-2 break-all">
                        {
                          threatIntel
                            .extracted_iocs
                            .urls
                            .join(", ")
                        }
                      </span>

                    </p>
                  )
                }


                {
                  threatIntel
                    .extracted_iocs
                    .hashes
                    .length > 0 && (
                    <div className="mt-2">

                      <p>
                        Hashes:
                      </p>


                      <pre
                        className="
                          mt-2
                          whitespace-pre-wrap
                          break-all
                          text-sm
                        "
                      >
                        {
                          JSON.stringify(
                            threatIntel
                              .extracted_iocs
                              .hashes,
                            null,
                            2
                          )
                        }
                      </pre>

                    </div>
                  )
                }


                {
                  threatIntel
                    .ioc_count ===
                    0 && (
                    <p className="mt-2">
                      No indicators extracted
                    </p>
                  )
                }

              </div>


              {/* PROVIDER RESULTS */}

              <div>

                <h3 className="font-semibold">
                  Provider Results
                </h3>


                {
                  threatIntel
                    .threat_intelligence
                    .length === 0 ? (
                    <p className="mt-2">
                      No enrichment results
                    </p>
                  ) : (
                    threatIntel
                      .threat_intelligence
                      .map(
                        (
                          item,
                          index
                        ) => (
                          <div
                            key={
                              index
                            }
                            className="
                              mt-3
                              rounded-lg
                              border
                              p-4
                            "
                          >
                            <pre
                              className="
                                whitespace-pre-wrap
                                break-all
                                text-sm
                              "
                            >
                              {
                                JSON.stringify(
                                  item,
                                  null,
                                  2
                                )
                              }
                            </pre>
                          </div>
                        )
                      )
                  )
                }

              </div>

            </div>
          )
        }

      </section>

    </main>
  );
}