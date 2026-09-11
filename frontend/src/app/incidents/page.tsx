"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

import { apiRequest } from "@/lib/api";
import { initKeycloak } from "@/lib/keycloak-auth";


type IncidentDisposition =
  | "unknown"
  | "true_positive"
  | "false_positive"
  | "benign";


type Incident = {
  id: number;
  title: string;
  description?: string | null;

  severity: string;
  status: string;
  disposition: IncidentDisposition;

  source?: string | null;

  hostname?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;

  assigned_to?: string | null;

  correlation_id?: string | null;

  event_timestamp?: string | null;

  detected_at: string;
  resolved_at?: string | null;
  created_at: string;

  workflow_status: string;
  workflow_error?: string | null;
};


type Filters = {
  search: string;
  severity: string;
  status: string;
  source: string;
  workflowStatus: string;
};


const initialFilters: Filters = {
  search: "",
  severity: "all",
  status: "all",
  source: "all",
  workflowStatus: "all",
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


function badgeClass(
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

    case "open":
      return (
        "border-cyan-500/40 " +
        "bg-cyan-500/10 " +
        "text-cyan-300"
      );

    case "closed":
    case "resolved":
    case "completed":
      return (
        "border-emerald-500/40 " +
        "bg-emerald-500/10 " +
        "text-emerald-400"
      );

    case "failed":
    case "rate_limited":
      return (
        "border-red-500/40 " +
        "bg-red-500/10 " +
        "text-red-400"
      );

    case "waiting_for_human":
      return (
        "border-violet-500/40 " +
        "bg-violet-500/10 " +
        "text-violet-300"
      );

    case "running":
      return (
        "border-blue-500/40 " +
        "bg-blue-500/10 " +
        "text-blue-300"
      );

    default:
      return (
        "border-slate-500/40 " +
        "bg-slate-500/10 " +
        "text-slate-300"
      );
  }
}


function Badge({
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
        badgeClass(value),
      ].join(" ")}
    >
      {value || "unknown"}
    </span>
  );
}


export default function IncidentsPage() {

  const router =
    useRouter();


  const [incidents, setIncidents] =
    useState<Incident[]>([]);


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


  // =====================================================
  // REFRESH INCIDENTS
  // =====================================================

  async function refreshIncidents() {

    try {

      setRefreshing(true);
      setError(null);


      const authenticated =
        await initKeycloak();


      if (!authenticated) {

        router.push(
          "/login"
        );

        return;
      }


      const data =
        await apiRequest<Incident[]>(
          "/incidents"
        );


      setIncidents(
        data
      );


    } catch (requestError) {

      console.error(
        "Unable to refresh incidents:",
        requestError
      );


      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to refresh incidents"
      );


    } finally {

      setRefreshing(false);

    }

  }


  // =====================================================
  // INITIAL LOAD
  // =====================================================

  useEffect(() => {

    let active =
      true;


    async function loadInitialIncidents() {

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
          await apiRequest<Incident[]>(
            "/incidents"
          );


        if (!active) {
          return;
        }


        setIncidents(
          data
        );


      } catch (requestError) {

        console.error(
          "Unable to load incidents:",
          requestError
        );


        if (!active) {
          return;
        }


        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to load incidents"
        );


      } finally {

        if (active) {

          setLoading(false);

        }

      }

    }


    void loadInitialIncidents();


    return () => {

      active =
        false;

    };

  }, [router]);


  // =====================================================
  // FILTER OPTIONS
  // =====================================================

  const severities =
    useMemo(
      () =>
        Array.from(
          new Set(
            incidents
              .map(
                (incident) =>
                  incident.severity
              )
              .filter(Boolean)
          )
        ).sort(),
      [incidents]
    );


  const statuses =
    useMemo(
      () =>
        Array.from(
          new Set(
            incidents
              .map(
                (incident) =>
                  incident.status
              )
              .filter(Boolean)
          )
        ).sort(),
      [incidents]
    );


  const sources =
    useMemo(
      () =>
        Array.from(
          new Set(
            incidents
              .map(
                (incident) =>
                  incident.source
              )
              .filter(
                (
                  value
                ): value is string =>
                  Boolean(value)
              )
          )
        ).sort(),
      [incidents]
    );


  const workflowStatuses =
    useMemo(
      () =>
        Array.from(
          new Set(
            incidents
              .map(
                (incident) =>
                  incident.workflow_status
              )
              .filter(Boolean)
          )
        ).sort(),
      [incidents]
    );


  // =====================================================
  // FILTERED INCIDENTS
  // =====================================================

  const filteredIncidents =
    useMemo(() => {

      const search =
        normalize(
          filters.search
        );


      return incidents.filter(
        (incident) => {

          const matchesSearch =
            !search ||
            [
              String(
                incident.id
              ),
              incident.title,
              incident.description,
              incident.source,
              incident.hostname,
              incident.source_ip,
              incident.destination_ip,
              incident.username,
              incident.assigned_to,
              incident.correlation_id,
              incident.workflow_status,
            ].some(
              (value) =>
                normalize(
                  value
                ).includes(
                  search
                )
            );


          const matchesSeverity =
            filters.severity === "all" ||
            normalize(
              incident.severity
            ) ===
              normalize(
                filters.severity
              );


          const matchesStatus =
            filters.status === "all" ||
            normalize(
              incident.status
            ) ===
              normalize(
                filters.status
              );


          const matchesSource =
            filters.source === "all" ||
            normalize(
              incident.source
            ) ===
              normalize(
                filters.source
              );


          const matchesWorkflow =
            filters.workflowStatus === "all" ||
            normalize(
              incident.workflow_status
            ) ===
              normalize(
                filters.workflowStatus
              );


          return (
            matchesSearch &&
            matchesSeverity &&
            matchesStatus &&
            matchesSource &&
            matchesWorkflow
          );

        }
      );

    }, [
      incidents,
      filters,
    ]);


  // =====================================================
  // COUNTERS
  // =====================================================

  const totals =
    useMemo(
      () => ({
        total:
          incidents.length,

        critical:
          incidents.filter(
            (incident) =>
              normalize(
                incident.severity
              ) === "critical"
          ).length,

        high:
          incidents.filter(
            (incident) =>
              normalize(
                incident.severity
              ) === "high"
          ).length,

        waiting:
          incidents.filter(
            (incident) =>
              normalize(
                incident.workflow_status
              ) ===
                "waiting_for_human"
          ).length,
      }),
      [incidents]
    );


  // =====================================================
  // LOADING
  // =====================================================

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
          Loading incidents...
        </div>

      </main>

    );

  }


  // =====================================================
  // UI
  // =====================================================

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
          max-w-[1700px]
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
              Security Operations Center
            </p>


            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              Incidents
            </h1>


            <p
              className="
                mt-2
                text-sm
                text-slate-400
              "
            >
              Review, filter and investigate
              security incidents detected by the SOC.
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
                  void refreshIncidents()
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
                disabled:cursor-not-allowed
                disabled:opacity-60
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
            xl:grid-cols-4
          "
        >

          <div
            className="
              rounded-xl
              border
              border-slate-700
              bg-[#0b1622]
              p-5
            "
          >
            <p
              className="
                text-xs
                uppercase
                tracking-wider
                text-slate-400
              "
            >
              Total Incidents
            </p>

            <p
              className="
                mt-3
                text-3xl
                font-bold
              "
            >
              {totals.total}
            </p>
          </div>


          <div
            className="
              rounded-xl
              border
              border-red-500/30
              bg-[#0b1622]
              p-5
            "
          >
            <p
              className="
                text-xs
                uppercase
                tracking-wider
                text-slate-400
              "
            >
              Critical
            </p>

            <p
              className="
                mt-3
                text-3xl
                font-bold
                text-red-400
              "
            >
              {totals.critical}
            </p>
          </div>


          <div
            className="
              rounded-xl
              border
              border-orange-500/30
              bg-[#0b1622]
              p-5
            "
          >
            <p
              className="
                text-xs
                uppercase
                tracking-wider
                text-slate-400
              "
            >
              High
            </p>

            <p
              className="
                mt-3
                text-3xl
                font-bold
                text-orange-400
              "
            >
              {totals.high}
            </p>
          </div>


          <div
            className="
              rounded-xl
              border
              border-violet-500/30
              bg-[#0b1622]
              p-5
            "
          >
            <p
              className="
                text-xs
                uppercase
                tracking-wider
                text-slate-400
              "
            >
              Waiting for Human
            </p>

            <p
              className="
                mt-3
                text-3xl
                font-bold
                text-violet-300
              "
            >
              {totals.waiting}
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
              xl:grid-cols-5
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
              placeholder="
                Search ID, title, IP, hostname, user...
              "
              className="
                rounded-lg
                border
                border-slate-600
                bg-[#07111c]
                px-3
                py-2
                text-sm
                outline-none
                focus:border-cyan-500
              "
            />


            <select
              value={
                filters.severity
              }
              onChange={
                (event) =>
                  setFilters(
                    (current) => ({
                      ...current,
                      severity:
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
                text-sm
              "
            >

              <option value="all">
                All severities
              </option>


              {
                severities.map(
                  (severity) => (

                    <option
                      key={
                        severity
                      }
                      value={
                        severity
                      }
                    >
                      {severity}
                    </option>

                  )
                )
              }

            </select>


            <select
              value={
                filters.status
              }
              onChange={
                (event) =>
                  setFilters(
                    (current) => ({
                      ...current,
                      status:
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
                text-sm
              "
            >

              <option value="all">
                All statuses
              </option>


              {
                statuses.map(
                  (status) => (

                    <option
                      key={
                        status
                      }
                      value={
                        status
                      }
                    >
                      {status}
                    </option>

                  )
                )
              }

            </select>


            <select
              value={
                filters.source
              }
              onChange={
                (event) =>
                  setFilters(
                    (current) => ({
                      ...current,
                      source:
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
                text-sm
              "
            >

              <option value="all">
                All sources
              </option>


              {
                sources.map(
                  (source) => (

                    <option
                      key={
                        source
                      }
                      value={
                        source
                      }
                    >
                      {source}
                    </option>

                  )
                )
              }

            </select>


            <select
              value={
                filters.workflowStatus
              }
              onChange={
                (event) =>
                  setFilters(
                    (current) => ({
                      ...current,
                      workflowStatus:
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
                text-sm
              "
            >

              <option value="all">
                All workflow states
              </option>


              {
                workflowStatuses.map(
                  (
                    workflowStatus
                  ) => (

                    <option
                      key={
                        workflowStatus
                      }
                      value={
                        workflowStatus
                      }
                    >
                      {
                        workflowStatus
                      }
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
              <strong
                className="
                  text-slate-100
                "
              >
                {
                  filteredIncidents.length
                }
              </strong>{" "}
              of{" "}
              <strong
                className="
                  text-slate-100
                "
              >
                {incidents.length}
              </strong>{" "}
              incidents
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

          <div
            className="
              overflow-x-auto
            "
          >

            <table
              className="
                min-w-full
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

                  <th className="px-4 py-4">
                    ID
                  </th>

                  <th className="px-4 py-4">
                    Incident
                  </th>

                  <th className="px-4 py-4">
                    Severity
                  </th>

                  <th className="px-4 py-4">
                    Status
                  </th>

                  <th className="px-4 py-4">
                    Source
                  </th>

                  <th className="px-4 py-4">
                    Host / IP
                  </th>

                  <th className="px-4 py-4">
                    Workflow
                  </th>

                  <th className="px-4 py-4">
                    Detected
                  </th>

                  <th className="px-4 py-4">
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
                  filteredIncidents.map(
                    (incident) => (

                      <tr
                        key={
                          incident.id
                        }
                        className="
                          transition
                          hover:bg-slate-800/40
                        "
                      >

                        <td
                          className="
                            whitespace-nowrap
                            px-4
                            py-4
                            font-mono
                            text-sm
                            text-cyan-300
                          "
                        >
                          #{incident.id}
                        </td>


                        <td
                          className="
                            min-w-[320px]
                            px-4
                            py-4
                          "
                        >

                          <p
                            className="
                              font-semibold
                              text-slate-100
                            "
                          >
                            {
                              incident.title
                            }
                          </p>


                          {
                            incident.description && (

                              <p
                                className="
                                  mt-1
                                  line-clamp-2
                                  text-sm
                                  text-slate-400
                                "
                              >
                                {
                                  incident.description
                                }
                              </p>

                            )
                          }


                          {
                            incident.correlation_id && (

                              <p
                                className="
                                  mt-2
                                  text-xs
                                  text-slate-500
                                "
                              >
                                Correlation:{" "}

                                <span
                                  className="
                                    font-mono
                                  "
                                >
                                  {
                                    incident.correlation_id
                                  }
                                </span>
                              </p>

                            )
                          }

                        </td>


                        <td
                          className="
                            whitespace-nowrap
                            px-4
                            py-4
                          "
                        >
                          <Badge
                            value={
                              incident.severity
                            }
                          />
                        </td>


                        <td
                          className="
                            whitespace-nowrap
                            px-4
                            py-4
                          "
                        >
                          <Badge
                            value={
                              incident.status
                            }
                          />
                        </td>


                        <td
                          className="
                            whitespace-nowrap
                            px-4
                            py-4
                            text-sm
                          "
                        >
                          {
                            incident.source ||
                            "—"
                          }
                        </td>


                        <td
                          className="
                            min-w-[220px]
                            px-4
                            py-4
                            text-sm
                            text-slate-300
                          "
                        >

                          <div>
                            {
                              incident.hostname ||
                              "Unknown host"
                            }
                          </div>

                          <div
                            className="
                              mt-1
                              font-mono
                              text-xs
                              text-slate-500
                            "
                          >
                            {
                              incident.source_ip ||
                              "No source IP"
                            }
                          </div>

                        </td>


                        <td
                          className="
                            whitespace-nowrap
                            px-4
                            py-4
                          "
                        >

                          <Badge
                            value={
                              incident.workflow_status
                            }
                          />


                          {
                            incident.workflow_error && (

                              <p
                                title={
                                  incident.workflow_error
                                }
                                className="
                                  mt-2
                                  max-w-[220px]
                                  truncate
                                  text-xs
                                  text-red-400
                                "
                              >
                                {
                                  incident.workflow_error
                                }
                              </p>

                            )
                          }

                        </td>


                        <td
                          className="
                            whitespace-nowrap
                            px-4
                            py-4
                            text-sm
                            text-slate-400
                          "
                        >
                          {
                            formatDate(
                              incident.detected_at
                            )
                          }
                        </td>


                        <td
                          className="
                            whitespace-nowrap
                            px-4
                            py-4
                          "
                        >

                          <button
                            type="button"
                            onClick={
                              () =>
                                router.push(
                                  `/incidents/${incident.id}`
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
                            "
                          >
                            Investigate
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
            filteredIncidents.length === 0 && (

              <div
                className="
                  p-10
                  text-center
                  text-slate-400
                "
              >
                No incidents match the current filters.
              </div>

            )
          }

        </section>

      </div>

    </main>

  );

}