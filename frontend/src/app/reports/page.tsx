"use client";

import {
  useEffect,
  useMemo,
  useState,
} from "react";

import { useRouter } from "next/navigation";

import { apiRequest } from "@/lib/api";
import { initKeycloak } from "@/lib/keycloak-auth";


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


export default function ReportsPage() {
  const router =
    useRouter();


  const [reports, setReports] =
    useState<SOCReport[]>([]);


  const [loading, setLoading] =
    useState(true);


  const [refreshing, setRefreshing] =
    useState(false);


  const [error, setError] =
    useState<string | null>(
      null
    );


  const [filters, setFilters] =
    useState<Filters>(
      initialFilters
    );


  const [
    selectedReport,
    setSelectedReport,
  ] =
    useState<SOCReport | null>(
      null
    );


  const [
    detailLoading,
    setDetailLoading,
  ] =
    useState(false);


  // =====================================================
  // INITIAL LOAD
  // =====================================================

  useEffect(() => {
    let active =
      true;

    async function loadInitialReports() {
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

        const data =
          await apiRequest<
            SOCReport[]
          >(
            "/reports"
          );

        if (!active) {
          return;
        }

        setReports(
          data
        );

      } catch (requestError) {
        console.error(
          "Unable to load SOC reports:",
          requestError
        );

        if (!active) {
          return;
        }

        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to load SOC reports"
        );

      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    void loadInitialReports();

    return () => {
      active =
        false;
    };

  }, [router]);


  // =====================================================
  // REFRESH
  // =====================================================

  async function refreshReports() {
    try {
      setRefreshing(
        true
      );

      setError(
        null
      );

      const data =
        await apiRequest<
          SOCReport[]
        >(
          "/reports"
        );

      setReports(
        data
      );

      if (selectedReport) {
        const updated =
          data.find(
            (report) =>
              report.id ===
              selectedReport.id
          );

        if (updated) {
          setSelectedReport(
            updated
          );
        }
      }

    } catch (requestError) {
      console.error(
        "Unable to refresh SOC reports:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to refresh SOC reports"
      );

    } finally {
      setRefreshing(
        false
      );
    }
  }


  // =====================================================
  // LOAD DETAIL
  // =====================================================

  async function loadReportDetail(
    reportId: number
  ) {
    try {
      setDetailLoading(
        true
      );

      setError(
        null
      );

      const report =
        await apiRequest<
          SOCReport
        >(
          `/reports/${reportId}`
        );

      setSelectedReport(
        report
      );

    } catch (requestError) {
      console.error(
        "Unable to load report detail:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to load report detail"
      );

    } finally {
      setDetailLoading(
        false
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
            reports
              .map(
                (report) =>
                  report.risk_level
              )
              .filter(Boolean)
          )
        ).sort(),
      [reports]
    );


  const responseStatuses =
    useMemo(
      () =>
        Array.from(
          new Set(
            reports
              .map(
                (report) =>
                  report.response_status
              )
              .filter(
                (
                  value
                ): value is string =>
                  Boolean(value)
              )
          )
        ).sort(),
      [reports]
    );


  const humanReviewStatuses =
    useMemo(
      () =>
        Array.from(
          new Set(
            reports
              .map(
                (report) =>
                  report.human_review_status
              )
              .filter(
                (
                  value
                ): value is string =>
                  Boolean(value)
              )
          )
        ).sort(),
      [reports]
    );


  // =====================================================
  // FILTERED REPORTS
  // =====================================================

  const filteredReports =
    useMemo(() => {
      const search =
        normalize(
          filters.search
        );

      return reports.filter(
        (report) => {
          const matchesSearch =
            !search ||
            [
              String(
                report.id
              ),
              String(
                report.incident_id
              ),
              String(
                report.ai_analysis_id ?? ""
              ),
              report.thread_id,
              report.title,
              report.summary,
              report.risk_level,
              report.ml_prediction,
              report.ml_engine,
              report.mitre_technique,
              report.mitre_name,
              report.recommendation,
              report.response_status,
              report.human_review_status,
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
              report.risk_level
            ) ===
              normalize(
                filters.risk
              );

          const matchesResponse =
            filters.responseStatus === "all" ||
            normalize(
              report.response_status
            ) ===
              normalize(
                filters.responseStatus
              );

          const matchesReview =
            filters.humanReviewStatus === "all" ||
            normalize(
              report.human_review_status
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
      reports,
      filters,
    ]);


  // =====================================================
  // KPI
  // =====================================================

  const totals =
    useMemo(
      () => ({
        total:
          reports.length,

        critical:
          reports.filter(
            (report) =>
              normalize(
                report.risk_level
              ) === "critical"
          ).length,

        high:
          reports.filter(
            (report) =>
              normalize(
                report.risk_level
              ) === "high"
          ).length,

        humanReview:
          reports.filter(
            (report) =>
              normalize(
                report.human_review_status
              ) ===
                "waiting_for_human" ||
              normalize(
                report.human_review_status
              ) ===
                "pending"
          ).length,

        anomalies:
          reports.filter(
            (report) =>
              report.ml_is_anomaly ===
              true
          ).length,
      }),
      [reports]
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
          Loading SOC reports...
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
              AI-Powered SOC Reporting
            </p>

            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              SOC Reports
            </h1>

            <p
              className="
                mt-2
                text-sm
                text-slate-400
              "
            >
              Review generated SOC reports,
              ML analysis, MITRE mapping,
              human review and AI recommendations.
            </p>
          </div>


          <div
            className="
              flex
              flex-wrap
              gap-3
            "
          >
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
                  void refreshReports()
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
              Total Reports
            </p>

            <p className="mt-3 text-3xl font-bold">
              {totals.total}
            </p>
          </div>


          <div className="rounded-xl border border-red-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Critical Risk
            </p>

            <p className="mt-3 text-3xl font-bold text-red-400">
              {totals.critical}
            </p>
          </div>


          <div className="rounded-xl border border-orange-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              High Risk
            </p>

            <p className="mt-3 text-3xl font-bold text-orange-400">
              {totals.high}
            </p>
          </div>


          <div className="rounded-xl border border-violet-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Human Review
            </p>

            <p className="mt-3 text-3xl font-bold text-violet-300">
              {totals.humanReview}
            </p>
          </div>


          <div className="rounded-xl border border-yellow-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              ML Anomalies
            </p>

            <p className="mt-3 text-3xl font-bold text-yellow-300">
              {totals.anomalies}
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
              placeholder="Search report, incident, MITRE, ML..."
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
                All response statuses
              </option>

              {
                responseStatuses.map(
                  (responseStatus) => (
                    <option
                      key={
                        responseStatus
                      }
                      value={
                        responseStatus
                      }
                    >
                      {responseStatus}
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
                humanReviewStatuses.map(
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
                  filteredReports.length
                }
              </strong>{" "}
              of{" "}
              <strong className="text-slate-100">
                {
                  reports.length
                }
              </strong>{" "}
              reports
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


        {/* REPORT TABLE */}

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
                min-w-[1500px]
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

                  <th className="w-[430px] px-4 py-4">
                    Report
                  </th>

                  <th className="w-[130px] px-4 py-4">
                    Incident
                  </th>

                  <th className="w-[130px] px-4 py-4">
                    Risk
                  </th>

                  <th className="w-[180px] px-4 py-4">
                    ML
                  </th>

                  <th className="w-[190px] px-4 py-4">
                    MITRE
                  </th>

                  <th className="w-[180px] px-4 py-4">
                    Response
                  </th>

                  <th className="w-[200px] px-4 py-4">
                    Created
                  </th>

                  <th className="w-[120px] px-4 py-4">
                    Action
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
                  filteredReports.map(
                    (report) => (
                      <tr
                        key={
                          report.id
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
                          #{report.id}
                        </td>


                        <td
                          className="
                            px-4
                            py-4
                          "
                        >
                          <p
                            title={
                              report.title
                            }
                            className="
                              truncate
                              font-semibold
                              text-slate-100
                            "
                          >
                            {report.title}
                          </p>

                          <p
                            title={
                              report.summary
                            }
                            className="
                              mt-1
                              line-clamp-2
                              text-sm
                              text-slate-400
                            "
                          >
                            {report.summary}
                          </p>
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
                                  `/incidents/${report.incident_id}`
                                )
                            }
                            className="
                              text-cyan-300
                              hover:underline
                            "
                          >
                            #
                            {
                              report.incident_id
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
                              report.risk_level
                            }
                          />
                        </td>


                        <td
                          className="
                            px-4
                            py-4
                            text-sm
                            text-slate-300
                          "
                        >
                          <p>
                            {
                              report.ml_prediction ||
                              "—"
                            }
                          </p>

                          {
                            report.ml_engine && (
                              <p
                                className="
                                  mt-1
                                  text-xs
                                  text-slate-500
                                "
                              >
                                {
                                  report.ml_engine
                                }
                              </p>
                            )
                          }
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
                              report.mitre_technique ||
                              "—"
                            }
                          </p>

                          {
                            report.mitre_name && (
                              <p
                                className="
                                  mt-1
                                  text-xs
                                  text-slate-500
                                "
                              >
                                {
                                  report.mitre_name
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
                              report.response_status
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
                              report.created_at
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
                            disabled={
                              detailLoading
                            }
                            onClick={
                              () =>
                                void loadReportDetail(
                                  report.id
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
                        </td>
                      </tr>
                    )
                  )
                }
              </tbody>
            </table>
          </div>


          {
            filteredReports.length === 0 && (
              <div
                className="
                  p-10
                  text-center
                  text-slate-400
                "
              >
                No SOC reports match
                the current filters.
              </div>
            )
          }
        </section>


        {/* REPORT DETAIL */}

        {
          selectedReport && (
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
                    SOC Report #
                    {
                      selectedReport.id
                    }
                  </p>

                  <h2
                    className="
                      mt-2
                      text-2xl
                      font-bold
                    "
                  >
                    {
                      selectedReport.title
                    }
                  </h2>

                  <p
                    className="
                      mt-2
                      text-sm
                      text-slate-400
                    "
                  >
                    Incident #
                    {
                      selectedReport.incident_id
                    }
                    {" · "}
                    {
                      formatDate(
                        selectedReport.created_at
                      )
                    }
                  </p>
                </div>


                <RiskBadge
                  value={
                    selectedReport.risk_level
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

                {/* SUMMARY */}

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
                    Executive Summary
                  </h3>

                  <p
                    className="
                      mt-4
                      whitespace-pre-wrap
                      text-sm
                      leading-6
                      text-slate-300
                    "
                  >
                    {
                      selectedReport.summary
                    }
                  </p>
                </div>


                {/* RECOMMENDATION */}

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
                      text-emerald-300
                    "
                  >
                    Recommendation
                  </h3>

                  <p
                    className="
                      mt-4
                      whitespace-pre-wrap
                      text-sm
                      leading-6
                      text-slate-300
                    "
                  >
                    {
                      selectedReport.recommendation ||
                      "No recommendation available."
                    }
                  </p>
                </div>


                {/* ML */}

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
                      text-yellow-300
                    "
                  >
                    Machine Learning
                  </h3>

                  <div
                    className="
                      mt-4
                      grid
                      gap-3
                      sm:grid-cols-2
                    "
                  >
                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Status
                      </p>

                      <p className="mt-1 text-sm">
                        {
                          selectedReport.ml_status ||
                          "—"
                        }
                      </p>
                    </div>


                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Prediction
                      </p>

                      <p className="mt-1 text-sm">
                        {
                          selectedReport.ml_prediction ||
                          "—"
                        }
                      </p>
                    </div>


                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Engine
                      </p>

                      <p className="mt-1 text-sm">
                        {
                          selectedReport.ml_engine ||
                          "—"
                        }
                      </p>
                    </div>


                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Anomaly
                      </p>

                      <p className="mt-1 text-sm">
                        {
                          selectedReport.ml_is_anomaly ===
                          null ||
                          selectedReport.ml_is_anomaly ===
                          undefined
                            ? "—"
                            : selectedReport.ml_is_anomaly
                              ? "Yes"
                              : "No"
                        }
                      </p>
                    </div>


                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Anomaly Score
                      </p>

                      <p className="mt-1 text-sm">
                        {
                          selectedReport.ml_anomaly_score ??
                          "—"
                        }
                      </p>
                    </div>
                  </div>


                  <pre
                    className="
                      mt-5
                      max-h-[360px]
                      overflow-auto
                      whitespace-pre-wrap
                      break-words
                      rounded-lg
                      border
                      border-slate-800
                      p-3
                      text-xs
                      text-slate-400
                    "
                  >
                    {
                      formatJson(
                        selectedReport.ml_probabilities
                      )
                    }
                  </pre>
                </div>


                {/* MITRE */}

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
                    MITRE ATT&CK
                  </h3>

                  <div
                    className="
                      mt-4
                      space-y-3
                    "
                  >
                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Technique
                      </p>

                      <p
                        className="
                          mt-1
                          font-mono
                          text-sm
                          text-violet-200
                        "
                      >
                        {
                          selectedReport.mitre_technique ||
                          "—"
                        }
                      </p>
                    </div>


                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Name
                      </p>

                      <p className="mt-1 text-sm">
                        {
                          selectedReport.mitre_name ||
                          "—"
                        }
                      </p>
                    </div>
                  </div>
                </div>


                {/* RESPONSE + HUMAN REVIEW */}

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
                    Response & Human Review
                  </h3>

                  <div
                    className="
                      mt-4
                      space-y-4
                    "
                  >
                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Response Status
                      </p>

                      <div className="mt-2">
                        <StatusBadge
                          value={
                            selectedReport.response_status
                          }
                        />
                      </div>
                    </div>


                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Human Review
                      </p>

                      <div className="mt-2">
                        <StatusBadge
                          value={
                            selectedReport.human_review_status
                          }
                        />
                      </div>
                    </div>


                    <div>
                      <p className="text-xs uppercase text-slate-500">
                        Analyst Comment
                      </p>

                      <p
                        className="
                          mt-2
                          whitespace-pre-wrap
                          text-sm
                          text-slate-300
                        "
                      >
                        {
                          selectedReport.human_comment ||
                          "No human comment."
                        }
                      </p>
                    </div>
                  </div>
                </div>


                {/* RAG SOURCES */}

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
                      text-emerald-300
                    "
                  >
                    RAG Sources
                  </h3>

                  {
                    selectedReport.rag_sources &&
                    selectedReport.rag_sources.length >
                      0 ? (
                      <ul
                        className="
                          mt-4
                          space-y-2
                          text-sm
                          text-slate-300
                        "
                      >
                        {
                          selectedReport.rag_sources.map(
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
                      <p
                        className="
                          mt-4
                          text-sm
                          text-slate-500
                        "
                      >
                        No RAG sources available.
                      </p>
                    )
                  }
                </div>


                {/* AGENT TRACE */}

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
                      text-violet-300
                    "
                  >
                    Agent Trace
                  </h3>

                  {
                    selectedReport.agent_trace &&
                    selectedReport.agent_trace.length >
                      0 ? (
                      <ol
                        className="
                          mt-4
                          space-y-2
                        "
                      >
                        {
                          selectedReport.agent_trace.map(
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
                                <span
                                  className="
                                    mr-2
                                    font-mono
                                    text-cyan-400
                                  "
                                >
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
                      <p
                        className="
                          mt-4
                          text-sm
                          text-slate-500
                        "
                      >
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