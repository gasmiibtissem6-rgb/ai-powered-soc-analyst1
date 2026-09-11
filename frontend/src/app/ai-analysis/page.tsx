"use client";

import {
  useEffect,
  useMemo,
  useState,
} from "react";

import { useRouter } from "next/navigation";

import {
  apiRequest,
  ApiError,
} from "@/lib/api";

import {
  initKeycloak,
  keycloak,
} from "@/lib/keycloak-auth";


type AIAnalysis = {
  id: number;
  incident_id: number;

  summary: string;
  risk_level: string;

  explanation?: string | null;
  recommendation?: string | null;

  mitre_technique?: string | null;
  mitre_name?: string | null;
  mitre_valid: boolean;

  rag_sources?: string[] | null;

  human_approval_required: boolean;
  human_approved?: boolean | null;
  human_review_status?: string | null;
  human_comment?: string | null;

  response_status?: string | null;

  thread_id?: string | null;
  agent_trace?: string[] | null;

  model_used?: string | null;

  created_at: string;
};


type GenerateResponse = {
  incident: {
    id: number;
    title: string;
    description?: string | null;
    severity: string;
    status: string;
    source?: string | null;
  };

  threat_intelligence: unknown[];

  analysis: {
    id: number;
    incident_id: number;

    summary: string;
    risk_level: string;

    explanation?: string | null;
    recommendation?: string | null;

    mitre_technique?: string | null;
    mitre_name?: string | null;
    mitre_valid: boolean;

    model_used?: string | null;
  };

  mitre_validation: {
    technique_id?: string | null;
    name?: string | null;
    description?: string | null;
    valid: boolean;
    error?: string | null;
  };
};


type KeycloakTokenParsed = {
  realm_access?: {
    roles?: string[];
  };

  resource_access?: Record<
    string,
    {
      roles?: string[];
    }
  >;
};


type Filters = {
  search: string;
  risk: string;
  responseStatus: string;
  humanReviewStatus: string;
};


const initialFilters: Filters = {
  search: "",
  risk: "all",
  responseStatus: "all",
  humanReviewStatus: "all",
};


function normalize(
  value?: string | null
) {
  return (
    value
      ?.trim()
      .toLowerCase()
    ?? ""
  );
}


function formatDate(
  value?: string | null
) {
  if (!value) {
    return "—";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return value;
  }

  return date.toLocaleString();
}


function formatJson(
  value: unknown
) {
  if (
    value === null ||
    value === undefined
  ) {
    return "—";
  }

  if (
    typeof value === "string"
  ) {
    return value;
  }

  try {
    return JSON.stringify(
      value,
      null,
      2
    );
  } catch {
    return String(value);
  }
}


function riskClass(
  value?: string | null
) {
  switch (
    normalize(value)
  ) {
    case "critical":
      return (
        "border-red-500/40 " +
        "bg-red-500/10 " +
        "text-red-400"
      );

    case "high":
      return (
        "border-orange-500/40 " +
        "bg-orange-500/10 " +
        "text-orange-400"
      );

    case "medium":
      return (
        "border-yellow-500/40 " +
        "bg-yellow-500/10 " +
        "text-yellow-300"
      );

    case "low":
      return (
        "border-emerald-500/40 " +
        "bg-emerald-500/10 " +
        "text-emerald-400"
      );

    default:
      return (
        "border-slate-500/40 " +
        "bg-slate-500/10 " +
        "text-slate-300"
      );
  }
}


function statusClass(
  value?: string | null
) {
  switch (
    normalize(value)
  ) {
    case "completed":
    case "approved":
    case "executed":
    case "simulated":
      return (
        "border-emerald-500/40 " +
        "bg-emerald-500/10 " +
        "text-emerald-400"
      );

    case "pending":
    case "waiting_for_human":
      return (
        "border-yellow-500/40 " +
        "bg-yellow-500/10 " +
        "text-yellow-300"
      );

    case "rejected":
    case "failed":
    case "execution_failed":
      return (
        "border-red-500/40 " +
        "bg-red-500/10 " +
        "text-red-400"
      );

    default:
      return (
        "border-slate-500/40 " +
        "bg-slate-500/10 " +
        "text-slate-300"
      );
  }
}


function RiskBadge({
  value,
}: {
  value?: string | null;
}) {
  return (
    <span
      className={[
        "inline-flex",
        "rounded-full",
        "border",
        "px-2.5",
        "py-1",
        "text-xs",
        "font-medium",
        riskClass(value),
      ].join(" ")}
    >
      {value || "unknown"}
    </span>
  );
}


function StatusBadge({
  value,
}: {
  value?: string | null;
}) {
  return (
    <span
      className={[
        "inline-flex",
        "rounded-full",
        "border",
        "px-2.5",
        "py-1",
        "text-xs",
        "font-medium",
        statusClass(value),
      ].join(" ")}
    >
      {value || "unknown"}
    </span>
  );
}


function getCurrentRoles() {
  const parsed =
    keycloak.tokenParsed as
      | KeycloakTokenParsed
      | undefined;

  const clientRoles =
    parsed
      ?.resource_access
      ?.[
        "soc-backend"
      ]
      ?.roles
    ?? [];

  const realmRoles =
    parsed
      ?.realm_access
      ?.roles
    ?? [];

  return Array.from(
    new Set([
      ...clientRoles,
      ...realmRoles,
    ])
  );
}


export default function AIAnalysisPage() {
  const router =
    useRouter();


  const [analyses, setAnalyses] =
    useState<AIAnalysis[]>([]);


  const [loading, setLoading] =
    useState(true);


  const [refreshing, setRefreshing] =
    useState(false);


  const [error, setError] =
    useState<string | null>(
      null
    );


  const [roles, setRoles] =
    useState<string[]>([]);


  const [filters, setFilters] =
    useState<Filters>(
      initialFilters
    );


  const [
    selectedAnalysis,
    setSelectedAnalysis,
  ] =
    useState<AIAnalysis | null>(
      null
    );


  const [
    detailLoading,
    setDetailLoading,
  ] =
    useState(false);


  const [
    generateIncidentId,
    setGenerateIncidentId,
  ] =
    useState("");


  const [
    generateLoading,
    setGenerateLoading,
  ] =
    useState(false);


  const [
    generateResult,
    setGenerateResult,
  ] =
    useState<GenerateResponse | null>(
      null
    );


  const [
    deleteLoading,
    setDeleteLoading,
  ] =
    useState<number | null>(
      null
    );


  // =====================================================
  // INITIAL LOAD
  // =====================================================

  useEffect(() => {
    let active =
      true;

    async function loadInitialAnalyses() {
      try {
        const authenticated =
          await initKeycloak();

        if (!active) {
          return;
        }

        if (!authenticated) {
          router.push(
            "/login"
          );

          return;
        }

        const currentRoles =
          getCurrentRoles();

        const data =
          await apiRequest<
            AIAnalysis[]
          >(
            "/ai-analysis"
          );

        if (!active) {
          return;
        }

        setRoles(
          currentRoles
        );

        setAnalyses(
          data
        );

      } catch (requestError) {
        console.error(
          "Unable to load AI analyses:",
          requestError
        );

        if (!active) {
          return;
        }

        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to load AI analyses"
        );

      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    void loadInitialAnalyses();

    return () => {
      active =
        false;
    };

  }, [router]);


  const isAdmin =
    roles.includes(
      "admin"
    );


  // =====================================================
  // REFRESH
  // =====================================================

  async function refreshAnalyses() {
    try {
      setRefreshing(
        true
      );

      setError(
        null
      );

      const data =
        await apiRequest<
          AIAnalysis[]
        >(
          "/ai-analysis"
        );

      setAnalyses(
        data
      );

      if (selectedAnalysis) {
        const updated =
          data.find(
            (analysis) =>
              analysis.id ===
              selectedAnalysis.id
          );

        if (updated) {
          setSelectedAnalysis(
            updated
          );
        }
      }

    } catch (requestError) {
      console.error(
        "Unable to refresh AI analyses:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to refresh AI analyses"
      );

    } finally {
      setRefreshing(
        false
      );
    }
  }


  // =====================================================
  // DETAIL
  // =====================================================

  async function loadAnalysisDetail(
    analysisId: number
  ) {
    try {
      setDetailLoading(
        true
      );

      setError(
        null
      );

      const analysis =
        await apiRequest<
          AIAnalysis
        >(
          `/ai-analysis/${analysisId}`
        );

      setSelectedAnalysis(
        analysis
      );

    } catch (requestError) {
      console.error(
        "Unable to load AI analysis detail:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to load AI analysis detail"
      );

    } finally {
      setDetailLoading(
        false
      );
    }
  }


  // =====================================================
  // GENERATE
  // =====================================================

  async function generateAnalysis() {
    const incidentId =
      Number(
        generateIncidentId
      );

    if (
      !Number.isInteger(
        incidentId
      ) ||
      incidentId <= 0
    ) {
      setError(
        "Enter a valid incident ID."
      );

      return;
    }

    try {
      setGenerateLoading(
        true
      );

      setError(
        null
      );

      setGenerateResult(
        null
      );

      const result =
        await apiRequest<
          GenerateResponse
        >(
          `/ai-analysis/generate/${incidentId}`,
          {
            method: "POST",
          }
        );

      setGenerateResult(
        result
      );

      const data =
        await apiRequest<
          AIAnalysis[]
        >(
          "/ai-analysis"
        );

      setAnalyses(
        data
      );

    } catch (requestError) {
      console.error(
        "AI analysis generation failed:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "AI analysis generation failed"
      );

    } finally {
      setGenerateLoading(
        false
      );
    }
  }


  // =====================================================
  // DELETE
  // =====================================================

  async function deleteAnalysis(
    analysis: AIAnalysis
  ) {
    if (!isAdmin) {
      setError(
        "Administrator privileges are required to delete AI analyses."
      );

      return;
    }

    const confirmed =
      window.confirm(
        `Delete AI analysis #${analysis.id}?`
      );

    if (!confirmed) {
      return;
    }

    try {
      setDeleteLoading(
        analysis.id
      );

      setError(
        null
      );

      await apiRequest<void>(
        `/ai-analysis/${analysis.id}`,
        {
          method: "DELETE",
        }
      );

      setAnalyses(
        (current) =>
          current.filter(
            (item) =>
              item.id !==
              analysis.id
          )
      );

      if (
        selectedAnalysis?.id ===
        analysis.id
      ) {
        setSelectedAnalysis(
          null
        );
      }

    } catch (requestError) {
      console.error(
        "Unable to delete AI analysis:",
        requestError
      );

      if (
        requestError instanceof ApiError &&
        requestError.status === 403
      ) {
        setError(
          "Administrator privileges are required to delete this AI analysis."
        );
      } else {
        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to delete AI analysis"
        );
      }

    } finally {
      setDeleteLoading(
        null
      );
    }
  }


  // =====================================================
  // FILTER OPTIONS
  // =====================================================

  const riskLevels =
    useMemo(
      () =>
        Array.from(
          new Set(
            analyses
              .map(
                (analysis) =>
                  analysis.risk_level
              )
              .filter(Boolean)
          )
        ).sort(),
      [analyses]
    );


  const responseStatuses =
    useMemo(
      () =>
        Array.from(
          new Set(
            analyses
              .map(
                (analysis) =>
                  analysis.response_status
              )
              .filter(
                (
                  value
                ): value is string =>
                  Boolean(value)
              )
          )
        ).sort(),
      [analyses]
    );


  const reviewStatuses =
    useMemo(
      () =>
        Array.from(
          new Set(
            analyses
              .map(
                (analysis) =>
                  analysis.human_review_status
              )
              .filter(
                (
                  value
                ): value is string =>
                  Boolean(value)
              )
          )
        ).sort(),
      [analyses]
    );


  // =====================================================
  // FILTERED DATA
  // =====================================================

  const filteredAnalyses =
    useMemo(() => {
      const search =
        normalize(
          filters.search
        );

      return analyses.filter(
        (analysis) => {
          const matchesSearch =
            !search ||
            [
              String(
                analysis.id
              ),
              String(
                analysis.incident_id
              ),
              analysis.summary,
              analysis.explanation,
              analysis.recommendation,
              analysis.risk_level,
              analysis.mitre_technique,
              analysis.mitre_name,
              analysis.response_status,
              analysis.human_review_status,
              analysis.thread_id,
              analysis.model_used,
            ].some(
              (value) =>
                normalize(
                  value
                ).includes(
                  search
                )
            );

          const matchesRisk =
            filters.risk === "all" ||
            normalize(
              analysis.risk_level
            ) ===
              normalize(
                filters.risk
              );

          const matchesResponse =
            filters.responseStatus === "all" ||
            normalize(
              analysis.response_status
            ) ===
              normalize(
                filters.responseStatus
              );

          const matchesReview =
            filters.humanReviewStatus === "all" ||
            normalize(
              analysis.human_review_status
            ) ===
              normalize(
                filters.humanReviewStatus
              );

          return (
            matchesSearch &&
            matchesRisk &&
            matchesResponse &&
            matchesReview
          );
        }
      );

    }, [
      analyses,
      filters,
    ]);


  // =====================================================
  // KPI
  // =====================================================

  const totals =
    useMemo(
      () => ({
        total:
          analyses.length,

        critical:
          analyses.filter(
            (analysis) =>
              normalize(
                analysis.risk_level
              ) === "critical"
          ).length,

        high:
          analyses.filter(
            (analysis) =>
              normalize(
                analysis.risk_level
              ) === "high"
          ).length,

        reviewRequired:
          analyses.filter(
            (analysis) =>
              analysis.human_approval_required ===
              true
          ).length,

        mitreValid:
          analyses.filter(
            (analysis) =>
              analysis.mitre_valid ===
              true
          ).length,
      }),
      [analyses]
    );


  if (loading) {
    return (
      <main
        className="
          min-h-screen
          bg-[#07111c]
          p-8
          text-slate-100
        "
      >
        <div
          className="
            rounded-xl
            border
            border-slate-700
            bg-[#0b1622]
            p-8
          "
        >
          Loading AI analyses...
        </div>
      </main>
    );
  }


  return (
    <main
      className="
        min-h-screen
        bg-[#07111c]
        p-8
        text-slate-100
      "
    >
      <div
        className="
          mx-auto
          max-w-[1750px]
          space-y-6
        "
      >

        {/* HEADER */}

        <section
          className="
            flex
            flex-col
            gap-4
            lg:flex-row
            lg:items-center
            lg:justify-between
          "
        >
          <div>
            <p
              className="
                text-sm
                uppercase
                tracking-[0.25em]
                text-cyan-400
              "
            >
              LLM-Assisted Security Investigation
            </p>

            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              AI Analysis
            </h1>

            <p
              className="
                mt-2
                text-sm
                text-slate-400
              "
            >
              Review generated AI investigations,
              threat intelligence context,
              MITRE ATT&CK mapping and recommendations.
            </p>
          </div>


          <div
            className="
              flex
              flex-wrap
              gap-3
            "
          >
            <div
              className="
                rounded-lg
                border
                border-slate-700
                bg-[#0b1622]
                px-4
                py-2
                text-sm
              "
            >
              Role:{" "}

              <strong
                className={
                  isAdmin
                    ? "text-emerald-400"
                    : "text-cyan-300"
                }
              >
                {
                  isAdmin
                    ? "Administrator"
                    : "Analyst"
                }
              </strong>
            </div>


            <button
              type="button"
              onClick={
                () =>
                  router.push(
                    "/incidents"
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
              Incidents
            </button>


            <button
              type="button"
              onClick={
                () =>
                  router.push(
                    "/dashboard"
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
              Back to Dashboard
            </button>


            <button
              type="button"
              disabled={
                refreshing
              }
              onClick={
                () =>
                  void refreshAnalyses()
              }
              className="
                rounded-lg
                bg-cyan-500
                px-4
                py-2
                text-sm
                font-semibold
                text-slate-950
                hover:bg-cyan-400
                disabled:opacity-50
              "
            >
              {
                refreshing
                  ? "Refreshing..."
                  : "Refresh"
              }
            </button>
          </div>
        </section>


        {/* ERROR */}

        {
          error && (
            <section
              className="
                rounded-xl
                border
                border-red-500/40
                bg-red-500/10
                p-4
                text-red-300
              "
            >
              {error}
            </section>
          )
        }


        {/* GENERATOR */}

        <section
          className="
            rounded-xl
            border
            border-violet-500/30
            bg-[#0b1622]
            p-6
          "
        >
          <h2
            className="
              text-xl
              font-bold
            "
          >
            Generate AI Analysis
          </h2>

          <p
            className="
              mt-2
              text-sm
              text-slate-400
            "
          >
            Generate a new investigation using
            Threat Intelligence, the configured LLM
            and MITRE ATT&CK validation.
          </p>


          <div
            className="
              mt-5
              flex
              flex-col
              gap-3
              sm:flex-row
            "
          >
            <input
              type="number"
              min="1"
              value={
                generateIncidentId
              }
              onChange={
                (event) =>
                  setGenerateIncidentId(
                    event.target.value
                  )
              }
              placeholder="Incident ID"
              className="
                min-w-[250px]
                rounded-lg
                border
                border-slate-600
                bg-[#07111c]
                px-3
                py-3
                outline-none
                focus:border-violet-500
              "
            />


            <button
              type="button"
              disabled={
                generateLoading
              }
              onClick={
                () =>
                  void generateAnalysis()
              }
              className="
                rounded-lg
                bg-violet-600
                px-5
                py-3
                font-semibold
                hover:bg-violet-500
                disabled:opacity-50
              "
            >
              {
                generateLoading
                  ? "Generating..."
                  : "Generate Analysis"
              }
            </button>
          </div>


          {
            generateResult && (
              <div
                className="
                  mt-6
                  grid
                  gap-5
                  xl:grid-cols-2
                "
              >
                <div
                  className="
                    rounded-xl
                    border
                    border-slate-700
                    bg-[#07111c]
                    p-5
                  "
                >
                  <h3
                    className="
                      font-semibold
                      text-cyan-300
                    "
                  >
                    Generated Analysis
                  </h3>

                  <div
                    className="
                      mt-4
                      space-y-3
                      text-sm
                    "
                  >
                    <p>
                      <strong>Incident:</strong>{" "}
                      #
                      {
                        generateResult.incident.id
                      }
                      {" · "}
                      {
                        generateResult.incident.title
                      }
                    </p>

                    <p>
                      <strong>Risk:</strong>{" "}
                      {
                        generateResult.analysis.risk_level
                      }
                    </p>

                    <p>
                      <strong>Model:</strong>{" "}
                      {
                        generateResult.analysis.model_used ||
                        "—"
                      }
                    </p>

                    <p>
                      <strong>MITRE:</strong>{" "}
                      {
                        generateResult.analysis.mitre_technique ||
                        "—"
                      }
                      {" "}
                      {
                        generateResult.analysis.mitre_name ||
                        ""
                      }
                    </p>
                  </div>


                  <p
                    className="
                      mt-5
                      whitespace-pre-wrap
                      text-sm
                      leading-6
                      text-slate-300
                    "
                  >
                    {
                      generateResult.analysis.summary
                    }
                  </p>
                </div>


                <div
                  className="
                    rounded-xl
                    border
                    border-slate-700
                    bg-[#07111c]
                    p-5
                  "
                >
                  <h3
                    className="
                      font-semibold
                      text-violet-300
                    "
                  >
                    MITRE Validation
                  </h3>

                  <pre
                    className="
                      mt-4
                      max-h-[320px]
                      overflow-auto
                      whitespace-pre-wrap
                      break-words
                      text-xs
                      text-slate-400
                    "
                  >
                    {
                      formatJson(
                        generateResult.mitre_validation
                      )
                    }
                  </pre>
                </div>


                <div
                  className="
                    rounded-xl
                    border
                    border-slate-700
                    bg-[#07111c]
                    p-5
                    xl:col-span-2
                  "
                >
                  <h3
                    className="
                      font-semibold
                      text-emerald-300
                    "
                  >
                    Threat Intelligence Context
                  </h3>

                  <pre
                    className="
                      mt-4
                      max-h-[420px]
                      overflow-auto
                      whitespace-pre-wrap
                      break-words
                      text-xs
                      text-slate-400
                    "
                  >
                    {
                      formatJson(
                        generateResult.threat_intelligence
                      )
                    }
                  </pre>
                </div>
              </div>
            )
          }
        </section>


        {/* KPI */}

        <section
          className="
            grid
            gap-4
            sm:grid-cols-2
            xl:grid-cols-5
          "
        >
          <div className="rounded-xl border border-slate-700 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Total Analyses
            </p>

            <p className="mt-3 text-3xl font-bold">
              {totals.total}
            </p>
          </div>


          <div className="rounded-xl border border-red-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Critical
            </p>

            <p className="mt-3 text-3xl font-bold text-red-400">
              {totals.critical}
            </p>
          </div>


          <div className="rounded-xl border border-orange-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              High
            </p>

            <p className="mt-3 text-3xl font-bold text-orange-400">
              {totals.high}
            </p>
          </div>


          <div className="rounded-xl border border-violet-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Human Approval
            </p>

            <p className="mt-3 text-3xl font-bold text-violet-300">
              {totals.reviewRequired}
            </p>
          </div>


          <div className="rounded-xl border border-emerald-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Valid MITRE
            </p>

            <p className="mt-3 text-3xl font-bold text-emerald-400">
              {totals.mitreValid}
            </p>
          </div>
        </section>


        {/* FILTERS */}

        <section
          className="
            rounded-xl
            border
            border-slate-700
            bg-[#0b1622]
            p-5
          "
        >
          <div
            className="
              grid
              gap-4
              md:grid-cols-2
              xl:grid-cols-4
            "
          >
            <input
              value={
                filters.search
              }
              onChange={
                (event) =>
                  setFilters(
                    (current) => ({
                      ...current,
                      search:
                        event.target.value,
                    })
                  )
              }
              placeholder="Search analysis, incident, MITRE, model..."
              className="
                rounded-lg
                border
                border-slate-600
                bg-[#07111c]
                px-3
                py-2
                outline-none
                focus:border-cyan-500
              "
            />


            <select
              value={
                filters.risk
              }
              onChange={
                (event) =>
                  setFilters(
                    (current) => ({
                      ...current,
                      risk:
                        event.target.value,
                    })
                  )
              }
              className="
                rounded-lg
                border
                border-slate-600
                bg-[#07111c]
                px-3
                py-2
              "
            >
              <option value="all">
                All risk levels
              </option>

              {
                riskLevels.map(
                  (risk) => (
                    <option
                      key={risk}
                      value={risk}
                    >
                      {risk}
                    </option>
                  )
                )
              }
            </select>


            <select
              value={
                filters.responseStatus
              }
              onChange={
                (event) =>
                  setFilters(
                    (current) => ({
                      ...current,
                      responseStatus:
                        event.target.value,
                    })
                  )
              }
              className="
                rounded-lg
                border
                border-slate-600
                bg-[#07111c]
                px-3
                py-2
              "
            >
              <option value="all">
                All response states
              </option>

              {
                responseStatuses.map(
                  (status) => (
                    <option
                      key={status}
                      value={status}
                    >
                      {status}
                    </option>
                  )
                )
              }
            </select>


            <select
              value={
                filters.humanReviewStatus
              }
              onChange={
                (event) =>
                  setFilters(
                    (current) => ({
                      ...current,
                      humanReviewStatus:
                        event.target.value,
                    })
                  )
              }
              className="
                rounded-lg
                border
                border-slate-600
                bg-[#07111c]
                px-3
                py-2
              "
            >
              <option value="all">
                All human review states
              </option>

              {
                reviewStatuses.map(
                  (status) => (
                    <option
                      key={status}
                      value={status}
                    >
                      {status}
                    </option>
                  )
                )
              }
            </select>
          </div>


          <div
            className="
              mt-4
              flex
              flex-wrap
              items-center
              justify-between
              gap-3
              text-sm
              text-slate-400
            "
          >
            <span>
              Showing{" "}
              <strong className="text-slate-100">
                {
                  filteredAnalyses.length
                }
              </strong>{" "}
              of{" "}
              <strong className="text-slate-100">
                {
                  analyses.length
                }
              </strong>{" "}
              analyses
            </span>


            <button
              type="button"
              onClick={
                () =>
                  setFilters(
                    initialFilters
                  )
              }
              className="
                rounded-lg
                border
                border-slate-600
                px-3
                py-1.5
                hover:bg-slate-800
              "
            >
              Reset filters
            </button>
          </div>
        </section>


        {/* TABLE */}

        <section
          className="
            overflow-hidden
            rounded-xl
            border
            border-slate-700
            bg-[#0b1622]
          "
        >
          <div className="overflow-x-auto">
            <table
              className="
                min-w-[1450px]
                w-full
                table-fixed
              "
            >
              <thead
                className="
                  border-b
                  border-slate-700
                  bg-[#0d1a28]
                  text-left
                  text-xs
                  uppercase
                  tracking-wider
                  text-slate-400
                "
              >
                <tr>
                  <th className="w-[90px] px-4 py-4">
                    ID
                  </th>

                  <th className="w-[460px] px-4 py-4">
                    Analysis
                  </th>

                  <th className="w-[120px] px-4 py-4">
                    Incident
                  </th>

                  <th className="w-[120px] px-4 py-4">
                    Risk
                  </th>

                  <th className="w-[200px] px-4 py-4">
                    MITRE
                  </th>

                  <th className="w-[180px] px-4 py-4">
                    Response
                  </th>

                  <th className="w-[190px] px-4 py-4">
                    Created
                  </th>

                  <th className="w-[190px] px-4 py-4">
                    Actions
                  </th>
                </tr>
              </thead>


              <tbody
                className="
                  divide-y
                  divide-slate-800
                "
              >
                {
                  filteredAnalyses.map(
                    (analysis) => {
                      const deleting =
                        deleteLoading ===
                        analysis.id;

                      return (
                        <tr
                          key={
                            analysis.id
                          }
                          className="
                            transition
                            hover:bg-slate-800/40
                          "
                        >
                          <td
                            className="
                              px-4
                              py-4
                              font-mono
                              text-sm
                              text-cyan-300
                            "
                          >
                            #{analysis.id}
                          </td>


                          <td
                            className="
                              px-4
                              py-4
                            "
                          >
                            <p
                              title={
                                analysis.summary
                              }
                              className="
                                line-clamp-2
                                font-semibold
                                text-slate-100
                              "
                            >
                              {
                                analysis.summary
                              }
                            </p>

                            {
                              analysis.model_used && (
                                <p
                                  className="
                                    mt-2
                                    truncate
                                    text-xs
                                    text-slate-500
                                  "
                                >
                                  Model:{" "}
                                  {
                                    analysis.model_used
                                  }
                                </p>
                              )
                            }
                          </td>


                          <td
                            className="
                              px-4
                              py-4
                            "
                          >
                            <button
                              type="button"
                              onClick={
                                () =>
                                  router.push(
                                    `/incidents/${analysis.incident_id}`
                                  )
                              }
                              className="
                                text-cyan-300
                                hover:underline
                              "
                            >
                              #
                              {
                                analysis.incident_id
                              }
                            </button>
                          </td>


                          <td
                            className="
                              px-4
                              py-4
                            "
                          >
                            <RiskBadge
                              value={
                                analysis.risk_level
                              }
                            />
                          </td>


                          <td
                            className="
                              px-4
                              py-4
                              text-sm
                            "
                          >
                            <p
                              className="
                                font-mono
                                text-violet-300
                              "
                            >
                              {
                                analysis.mitre_technique ||
                                "—"
                              }
                            </p>

                            {
                              analysis.mitre_name && (
                                <p
                                  className="
                                    mt-1
                                    truncate
                                    text-xs
                                    text-slate-500
                                  "
                                >
                                  {
                                    analysis.mitre_name
                                  }
                                </p>
                              )
                            }
                          </td>


                          <td
                            className="
                              px-4
                              py-4
                            "
                          >
                            <StatusBadge
                              value={
                                analysis.response_status
                              }
                            />
                          </td>


                          <td
                            className="
                              px-4
                              py-4
                              text-sm
                              text-slate-400
                            "
                          >
                            {
                              formatDate(
                                analysis.created_at
                              )
                            }
                          </td>


                          <td
                            className="
                              px-4
                              py-4
                            "
                          >
                            <div
                              className="
                                flex
                                flex-wrap
                                gap-2
                              "
                            >
                              <button
                                type="button"
                                disabled={
                                  detailLoading
                                }
                                onClick={
                                  () =>
                                    void loadAnalysisDetail(
                                      analysis.id
                                    )
                                }
                                className="
                                  rounded-lg
                                  border
                                  border-cyan-500/50
                                  px-3
                                  py-2
                                  text-sm
                                  text-cyan-300
                                  hover:bg-cyan-500/10
                                  disabled:opacity-50
                                "
                              >
                                Details
                              </button>


                              {
                                isAdmin && (
                                  <button
                                    type="button"
                                    disabled={
                                      deleting
                                    }
                                    onClick={
                                      () =>
                                        void deleteAnalysis(
                                          analysis
                                        )
                                    }
                                    className="
                                      rounded-lg
                                      border
                                      border-red-500/50
                                      px-3
                                      py-2
                                      text-sm
                                      text-red-400
                                      hover:bg-red-500/10
                                      disabled:opacity-50
                                    "
                                  >
                                    {
                                      deleting
                                        ? "Deleting..."
                                        : "Delete"
                                    }
                                  </button>
                                )
                              }
                            </div>
                          </td>
                        </tr>
                      );
                    }
                  )
                }
              </tbody>
            </table>
          </div>


          {
            filteredAnalyses.length === 0 && (
              <div
                className="
                  p-10
                  text-center
                  text-slate-400
                "
              >
                No AI analyses match
                the current filters.
              </div>
            )
          }
        </section>


        {/* DETAIL */}

        {
          selectedAnalysis && (
            <section
              className="
                rounded-xl
                border
                border-slate-700
                bg-[#0b1622]
                p-6
              "
            >
              <div
                className="
                  flex
                  flex-wrap
                  items-start
                  justify-between
                  gap-4
                "
              >
                <div>
                  <p
                    className="
                      text-xs
                      uppercase
                      tracking-[0.2em]
                      text-slate-500
                    "
                  >
                    AI Analysis #
                    {
                      selectedAnalysis.id
                    }
                  </p>

                  <h2
                    className="
                      mt-2
                      text-2xl
                      font-bold
                    "
                  >
                    Incident #
                    {
                      selectedAnalysis.incident_id
                    }
                  </h2>

                  <p
                    className="
                      mt-2
                      text-sm
                      text-slate-400
                    "
                  >
                    {
                      formatDate(
                        selectedAnalysis.created_at
                      )
                    }
                    {" · "}
                    {
                      selectedAnalysis.model_used ||
                      "Unknown model"
                    }
                  </p>
                </div>


                <RiskBadge
                  value={
                    selectedAnalysis.risk_level
                  }
                />
              </div>


              <div
                className="
                  mt-6
                  grid
                  gap-5
                  xl:grid-cols-2
                "
              >

                <div className="rounded-xl border border-slate-700 bg-[#07111c] p-5">
                  <h3 className="font-semibold text-cyan-300">
                    Summary
                  </h3>

                  <p className="mt-4 whitespace-pre-wrap text-sm leading-6 text-slate-300">
                    {
                      selectedAnalysis.summary
                    }
                  </p>
                </div>


                <div className="rounded-xl border border-slate-700 bg-[#07111c] p-5">
                  <h3 className="font-semibold text-violet-300">
                    Explanation
                  </h3>

                  <p className="mt-4 whitespace-pre-wrap text-sm leading-6 text-slate-300">
                    {
                      selectedAnalysis.explanation ||
                      "No explanation available."
                    }
                  </p>
                </div>


                <div className="rounded-xl border border-slate-700 bg-[#07111c] p-5">
                  <h3 className="font-semibold text-emerald-300">
                    Recommendation
                  </h3>

                  <p className="mt-4 whitespace-pre-wrap text-sm leading-6 text-slate-300">
                    {
                      selectedAnalysis.recommendation ||
                      "No recommendation available."
                    }
                  </p>
                </div>


                <div className="rounded-xl border border-slate-700 bg-[#07111c] p-5">
                  <h3 className="font-semibold text-violet-300">
                    MITRE ATT&CK
                  </h3>

                  <div className="mt-4 space-y-3 text-sm">
                    <p>
                      <strong>Technique:</strong>{" "}
                      {
                        selectedAnalysis.mitre_technique ||
                        "—"
                      }
                    </p>

                    <p>
                      <strong>Name:</strong>{" "}
                      {
                        selectedAnalysis.mitre_name ||
                        "—"
                      }
                    </p>

                    <p>
                      <strong>Validated:</strong>{" "}
                      {
                        selectedAnalysis.mitre_valid
                          ? "Yes"
                          : "No"
                      }
                    </p>
                  </div>
                </div>


                <div className="rounded-xl border border-slate-700 bg-[#07111c] p-5">
                  <h3 className="font-semibold text-cyan-300">
                    Human Review
                  </h3>

                  <div className="mt-4 space-y-3 text-sm">
                    <p>
                      <strong>Required:</strong>{" "}
                      {
                        selectedAnalysis.human_approval_required
                          ? "Yes"
                          : "No"
                      }
                    </p>

                    <p>
                      <strong>Approved:</strong>{" "}
                      {
                        selectedAnalysis.human_approved ===
                        null ||
                        selectedAnalysis.human_approved ===
                        undefined
                          ? "—"
                          : selectedAnalysis.human_approved
                            ? "Yes"
                            : "No"
                      }
                    </p>

                    <p>
                      <strong>Status:</strong>{" "}

                      <StatusBadge
                        value={
                          selectedAnalysis.human_review_status
                        }
                      />
                    </p>

                    <p className="whitespace-pre-wrap">
                      <strong>Comment:</strong>{" "}
                      {
                        selectedAnalysis.human_comment ||
                        "No human comment."
                      }
                    </p>
                  </div>
                </div>


                <div className="rounded-xl border border-slate-700 bg-[#07111c] p-5">
                  <h3 className="font-semibold text-emerald-300">
                    RAG Sources
                  </h3>

                  {
                    selectedAnalysis.rag_sources &&
                    selectedAnalysis.rag_sources.length >
                      0 ? (
                      <ul className="mt-4 space-y-2 text-sm text-slate-300">
                        {
                          selectedAnalysis.rag_sources.map(
                            (
                              source,
                              index
                            ) => (
                              <li
                                key={
                                  `${source}-${index}`
                                }
                                className="
                                  rounded-lg
                                  border
                                  border-slate-800
                                  p-3
                                  break-all
                                "
                              >
                                {source}
                              </li>
                            )
                          )
                        }
                      </ul>
                    ) : (
                      <p className="mt-4 text-sm text-slate-500">
                        No RAG sources available.
                      </p>
                    )
                  }
                </div>


                <div className="rounded-xl border border-slate-700 bg-[#07111c] p-5 xl:col-span-2">
                  <h3 className="font-semibold text-violet-300">
                    Agent Trace
                  </h3>

                  {
                    selectedAnalysis.agent_trace &&
                    selectedAnalysis.agent_trace.length >
                      0 ? (
                      <ol className="mt-4 space-y-2">
                        {
                          selectedAnalysis.agent_trace.map(
                            (
                              trace,
                              index
                            ) => (
                              <li
                                key={
                                  `${trace}-${index}`
                                }
                                className="
                                  rounded-lg
                                  border
                                  border-slate-800
                                  p-3
                                  text-sm
                                  text-slate-300
                                "
                              >
                                <span className="mr-2 font-mono text-cyan-400">
                                  {
                                    index + 1
                                  }.
                                </span>

                                {trace}
                              </li>
                            )
                          )
                        }
                      </ol>
                    ) : (
                      <p className="mt-4 text-sm text-slate-500">
                        No agent trace available.
                      </p>
                    )
                  }
                </div>

              </div>
            </section>
          )
        }

      </div>
    </main>
  );
}