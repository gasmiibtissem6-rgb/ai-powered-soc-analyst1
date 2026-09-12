"use client";

import { useEffect, useState } from "react";
import {
  useParams,
  useRouter,
} from "next/navigation";

import { apiRequest } from "@/lib/api";
import { initKeycloak } from "@/lib/keycloak-auth";


type Incident = {
  id: number;
  title: string;
  description: string;
  severity: string;
  status: string;
  source: string;

  hostname?: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;

  workflow_status?: string;
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
  status: "waiting_for_human" | "completed";
  thread_id: string;

  ai_analysis_id?: number;
  soc_report_id?: number;
  soar_action_id?: number | null;

  interrupt?: unknown[];

  incident?: Record<string, unknown>;
  correlated_incidents?: unknown[];

  triage?: Record<string, unknown> | null;
  ml_analysis?: Record<string, unknown> | null;
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

  response?: Record<string, unknown> | null;

  soar_action?: {
    action_type?: string;
    target?: string;
    status?: string;
    requires_approval?: boolean;
  } | null;

  report?: Record<string, unknown> | null;

  agent_trace?: string[];
};

export default function IncidentDetailsPage() {

  const params = useParams();
  const router = useRouter();

  const id = params.id as string;


  const [incident, setIncident] =
    useState<Incident | null>(null);


  const [analysis, setAnalysis] =
    useState<AIAnalysis[]>([]);


  const [aiAnalysis, setAiAnalysis] =
    useState<AIAnalysis | null>(null);


  const [threatIntel, setThreatIntel] =
    useState<ThreatIntel | null>(null);

  const [
  reports,
  setReports,
] =
  useState<SOCReport[]>(
    []
  );

  const [loading, setLoading] =
  useState(true);


const [aiLoading, setAiLoading] =
  useState(false);


const [aiError, setAiError] =
  useState<string | null>(null);


const [workflowLoading, setWorkflowLoading] =
  useState(false);


const [workflowError, setWorkflowError] =
  useState<string | null>(null);


const [workflowResult, setWorkflowResult] =
  useState<AgentWorkflowResponse | null>(null);


const [workflowThreadId, setWorkflowThreadId] =
  useState<string | null>(null);


const [workflowStatus, setWorkflowStatus] =
  useState<string | null>(null);


const [humanComment, setHumanComment] =
  useState("");


const [resumeLoading, setResumeLoading] =
  useState(false);

  // =====================================================
  // RUN AI ANALYSIS
  // =====================================================

  async function runAIInvestigation() {

    try {

      setAiLoading(true);

      setAiError(null);


      const result =
        await apiRequest<GenerateAIAnalysisResponse>(
          `/ai-analysis/generate/${id}`,
          {
            method: "POST",
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
              item.id !== result.analysis.id
          ),
        ]
      );


    } catch (error) {

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

      setAiLoading(false);

    }

  }






async function runFullSOCWorkflow() {
  try {
    setWorkflowLoading(true);
    setWorkflowError(null);

    const result =
  await apiRequest<AgentWorkflowResponse>(
      `/agents/analyze/${id}`,
      {
        method: "POST",
      }
    );

    setWorkflowResult(result);

    setWorkflowStatus(
      result.status ?? null
    );

    setWorkflowThreadId(
      result.thread_id ?? null
    );

    if (
      result.status === "completed"

    ) {
      const analysisData =
        await apiRequest<AIAnalysis[]>(
          `/ai-analysis/incident/${id}`
        );

      setAnalysis(analysisData);

      setAiAnalysis(
        analysisData.length > 0
          ? analysisData[0]
          : null
      );
    }

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
} catch (error) {
  console.log(
    "Unable to refresh SOC reports",
    error
  );
}

  } catch (error) {
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
    setWorkflowLoading(false);
  }
}

async function resumeSOCWorkflow(
  approved: boolean
) {
  if (!workflowThreadId) {
    setWorkflowError(
      "Missing workflow thread ID"
    );

    return;
  }

  try {
    setResumeLoading(true);
    setWorkflowError(null);

    const result =
      await apiRequest<AgentWorkflowResponse>(
        `/agents/resume/${workflowThreadId}`,
        {
          method: "POST",
          body: JSON.stringify({
            approved,
            comment:
              humanComment.trim() ||
              (
                approved
                  ? "Approved from SOC frontend"
                  : "Rejected from SOC frontend"
              ),
          }),
        }
      );

    setWorkflowResult(result);

    setWorkflowStatus(
      result.status ?? null
    );

    setWorkflowThreadId(
      result.thread_id ??
      workflowThreadId
    );

    if (
      result.status === "completed"
    ) {
      const analysisData =
        await apiRequest<AIAnalysis[]>(
          `/ai-analysis/incident/${id}`
        );

      setAnalysis(analysisData);

      setAiAnalysis(
        analysisData.length > 0
          ? analysisData[0]
          : null
      );
    }

  } catch (error) {
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
    setResumeLoading(false);
  }
}

  // =====================================================
  // LOAD INCIDENT DATA
  // =====================================================

  useEffect(() => {

    let active = true;


    async function load() {

      try {

        const authenticated =
          await initKeycloak();


        if (!authenticated) {

          console.log(
            "Not authenticated"
          );

          return;

        }



        const incidentData =
          await apiRequest<Incident>(
            `/incidents/${id}`
          );



        const analysisData =
          await apiRequest<AIAnalysis[]>(
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

} catch (error) {
  console.log(
    "No SOC reports available",
    error
  );
}

        let threatData:
          ThreatIntel | null = null;


        try {

          threatData =
            await apiRequest<ThreatIntel>(
              `/threat-intelligence/incident/${id}`
            );


        } catch (error) {

          console.log(
            "No threat intelligence data",
            error
          );

        }



        if (!active) {

          return;

        }



        setIncident(
          incidentData
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

        setReports(
  reportsData
);

      } catch (error) {

        console.error(
          "Unable to load incident:",
          error
        );


      } finally {

        if (active) {

          setLoading(false);

        }

      }

    }


    void load();


    return () => {

      active = false;

    };

  }, [id]);



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

  if (loading) {

    return (

      <div className="p-10">
        Loading incident...
      </div>

    );

  }



  // =====================================================
  // INCIDENT NOT FOUND
  // =====================================================

  if (!incident) {

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

          onClick={runAIInvestigation}

          disabled={aiLoading}

          className="
            mt-4
            bg-blue-600
            px-5
            py-2
            rounded-lg
            text-white
            disabled:opacity-50
            disabled:cursor-not-allowed
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

            <div className="mt-5 border rounded-lg p-4">


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

                  {aiAnalysis.risk_level}

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

                      {aiAnalysis.model_used}

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
    onClick={runFullSOCWorkflow}
    disabled={
      workflowLoading ||
      resumeLoading
    }
    className="
      mt-4
      bg-purple-600
      px-5
      py-2
      rounded-lg
      text-white
      disabled:opacity-50
      disabled:cursor-not-allowed
    "
  >
    {
      workflowLoading
        ? "Running SOC Workflow..."
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
    workflowResult && (
      <div className="mt-5 border rounded-lg p-4">

        <p>
          <b>Status:</b>

          <span className="ml-2">
            {workflowStatus}
          </span>
        </p>


        {
          workflowThreadId && (
            <p className="mt-2 break-all">
              <b>Thread ID:</b>

              <span className="ml-2">
                {workflowThreadId}
              </span>
            </p>
          )
        }


        {
          workflowResult.investigation && (
            <div className="mt-4">

              <h3 className="font-semibold">
                Investigation
              </h3>

              {
                workflowResult.investigation
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
                workflowResult.investigation
                  .summary && (
                  <p className="mt-2 whitespace-pre-wrap">
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
          workflowResult.mitre_validation && (
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
            workflowResult.agent_trace
          ) &&
          workflowResult.agent_trace.length > 0 && (

            <div className="mt-4">

              <h3 className="font-semibold">
                Agent Trace
              </h3>

              <ul className="list-disc ml-6 mt-2">

                {
                  workflowResult.agent_trace.map(
                    (
                      agent: string,
                      index: number
                    ) => (

                      <li key={index}>
                        {agent}
                      </li>

                    )
                  )
                }

              </ul>

            </div>
          )
        }


        {
          workflowStatus ===
            "waiting_for_human" && (

            <div className="mt-6 border rounded-lg p-4">

              <h3 className="font-semibold">
                Human Approval Required
              </h3>


              {
                Array.isArray(
                  workflowResult.interrupt
                ) && (

                  <pre className="
                    mt-3
                    text-sm
                    whitespace-pre-wrap
                    break-words
                  ">
                    {
                      JSON.stringify(
                        workflowResult.interrupt,
                        null,
                        2
                      )
                    }
                  </pre>
                )
              }


              <textarea
                value={humanComment}
                onChange={(event) =>
                  setHumanComment(
                    event.target.value
                  )
                }
                placeholder="Human review comment..."
                className="
                  mt-4
                  w-full
                  border
                  rounded-lg
                  p-3
                  bg-transparent
                "
              />


              <div className="flex gap-3 mt-4">

                <button
                  onClick={() =>
                    resumeSOCWorkflow(true)
                  }
                  disabled={resumeLoading}
                  className="
                    bg-green-600
                    px-4
                    py-2
                    rounded-lg
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
                  onClick={() =>
                    resumeSOCWorkflow(false)
                  }
                  disabled={resumeLoading}
                  className="
                    bg-red-600
                    px-4
                    py-2
                    rounded-lg
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


        {
          workflowStatus ===
            "completed" && (

            <div className="mt-5">

              <p className="font-semibold text-green-400">
                SOC workflow completed
              </p>


              {
                workflowResult
                  .ai_analysis_id && (
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
                  .soc_report_id && (
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
                  .soar_action_id && (
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

          {incident.title}

        </h2>



        <p className="mt-4 whitespace-pre-wrap break-words">

          {incident.description}

        </p>



        <div
          className="
            grid
            grid-cols-1
            md:grid-cols-3
            gap-4
            mt-6
          "
        >


          <div>

            Severity:

            <b className="ml-2">

              {incident.severity}

            </b>

          </div>



          <div>

            Status:

            <b className="ml-2">

              {incident.status}

            </b>

          </div>



          <div>

            Source:

            <b className="ml-2">

              {incident.source}

            </b>

          </div>


        </div>



        {
          (
            incident.hostname ||
            incident.source_ip ||
            incident.destination_ip ||
            incident.username
          ) && (

            <div
              className="
                grid
                grid-cols-1
                md:grid-cols-2
                gap-4
                mt-6
              "
            >


              {
                incident.hostname && (

                  <div>

                    Hostname:

                    <b className="ml-2">

                      {incident.hostname}

                    </b>

                  </div>

                )
              }



              {
                incident.source_ip && (

                  <div>

                    Source IP:

                    <b className="ml-2">

                      {incident.source_ip}

                    </b>

                  </div>

                )
              }



              {
                incident.destination_ip && (

                  <div>

                    Destination IP:

                    <b className="ml-2">

                      {incident.destination_ip}

                    </b>

                  </div>

                )
              }



              {
                incident.username && (

                  <div>

                    Username:

                    <b className="ml-2">

                      {incident.username}

                    </b>

                  </div>

                )
              }


            </div>

          )
        }


      </section>

      {/* =================================================
    SOC REPORTS
================================================= */}

<section
  className="
    rounded-xl
    border
    p-6
  "
>
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
      <h2
        className="
          text-xl
          font-bold
        "
      >
        SOC Reports
      </h2>

      <p
        className="
          mt-1
          text-sm
          text-slate-400
        "
      >
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
      <div
        className="
          mt-5
          space-y-4
        "
      >
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
                    <p
                      className="
                        text-sm
                        text-cyan-300
                      "
                    >
                      Report #
                      {
                        report.id
                      }
                    </p>

                    <h3
                      className="
                        mt-1
                        text-lg
                        font-semibold
                      "
                    >
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

                      <p
                        className="
                          mt-2
                          text-sm
                          leading-6
                        "
                      >
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
                    <span
                      className="
                        text-slate-500
                      "
                    >
                      MITRE:
                    </span>{" "}
                    {
                      report.mitre_technique
                      || "—"
                    }
                  </div>

                  <div>
                    <span
                      className="
                        text-slate-500
                      "
                    >
                      ML:
                    </span>{" "}
                    {
                      report.ml_prediction
                      || report.ml_status
                      || "—"
                    }
                  </div>

                  <div>
                    <span
                      className="
                        text-slate-500
                      "
                    >
                      Human Review:
                    </span>{" "}
                    {
                      report.human_review_status
                      || "—"
                    }
                  </div>

                  <div>
                    <span
                      className="
                        text-slate-500
                      "
                    >
                      Response:
                    </span>{" "}
                    {
                      report.response_status
                      || "—"
                    }
                  </div>
                </div>


                <p
                  className="
                    mt-4
                    text-xs
                    text-slate-500
                  "
                >
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
      <p
        className="
          mt-5
          text-sm
          text-slate-500
        "
      >
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

            <div className="mt-4 border rounded-lg p-4">


              <p>

                <b>
                  Risk:
                </b>

                <span className="ml-2">

                  {latestAnalysis.risk_level}

                </span>

              </p>



              <div className="mt-4">


                <p className="font-semibold">

                  Summary

                </p>


                <p className="mt-1 whitespace-pre-wrap">

                  {latestAnalysis.summary}

                </p>


              </div>



              {
                latestAnalysis.explanation && (

                  <div className="mt-4">


                    <p className="font-semibold">

                      Explanation

                    </p>


                    <p className="mt-1 whitespace-pre-wrap">

                      {latestAnalysis.explanation}

                    </p>


                  </div>

                )
              }



              {
                latestAnalysis.recommendation && (

                  <div className="mt-4">


                    <p className="font-semibold">

                      Recommendation

                    </p>


                    <p className="mt-1 whitespace-pre-line">

                      {latestAnalysis.recommendation}

                    </p>


                  </div>

                )
              }



              {
                latestAnalysis.mitre_technique && (

                  <p className="mt-4">


                    <b>
                      MITRE:
                    </b>


                    <span className="ml-2">

                      {
                        latestAnalysis.mitre_technique
                      }


                      {
                        latestAnalysis.mitre_name
                          ? ` - ${latestAnalysis.mitre_name}`
                          : ""
                      }


                    </span>


                  </p>

                )
              }



              {
                typeof latestAnalysis.mitre_valid ===
                "boolean" && (

                  <p className="mt-2">


                    <b>
                      MITRE Validation:
                    </b>


                    <span className="ml-2">

                      {
                        latestAnalysis.mitre_valid
                          ? "Valid"
                          : "Invalid"
                      }

                    </span>


                  </p>

                )
              }



              {
                latestAnalysis.model_used && (

                  <p className="mt-2">


                    <b>
                      Model:
                    </b>


                    <span className="ml-2">

                      {latestAnalysis.model_used}

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
                          text-sm
                          whitespace-pre-wrap
                          break-all
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
                  threatIntel.ioc_count === 0 && (

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
                        (item, index) => (

                          <div

                            key={index}

                            className="
                              border
                              rounded-lg
                              p-4
                              mt-3
                            "

                          >


                            <pre
                              className="
                                text-sm
                                whitespace-pre-wrap
                                break-all
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