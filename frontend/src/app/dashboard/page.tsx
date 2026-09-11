"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  useRouter,
} from "next/navigation";

import {
  apiRequest,
} from "@/lib/api";

import {
  initKeycloak,
  keycloak,
} from "@/lib/keycloak-auth";


// =====================================================
// TYPES
// =====================================================

type Metrics = {
  total_incidents: number;
  open_incidents?: number;
  resolved_incidents?: number;
  critical_incidents?: number;
};


type SeverityMetric = {
  severity: string;
  count: number;
};


type SeverityMetricsResponse =
  | SeverityMetric[]
  | Record<string, number>;


type Incident = {
  id: number;
  title: string;
  severity: string;
  status: string;
  source: string;
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


type NavigationItem = {
  title: string;
  description: string;
  route: string;
  category: string;
  adminOnly?: boolean;
};


// =====================================================
// NAVIGATION
// =====================================================

const navigationItems: NavigationItem[] = [
  {
    title: "Alerts",
    description:
      "Review security alerts from Wazuh, Suricata and other SOC sources.",
    route: "/alerts",
    category: "Monitoring",
  },

  {
    title: "Incidents",
    description:
      "Investigate correlated security incidents and their lifecycle.",
    route: "/incidents",
    category: "Investigation",
  },

  {
    title: "AI Analysis",
    description:
      "Generate and review LLM-assisted SOC investigations.",
    route: "/ai-analysis",
    category: "Artificial Intelligence",
  },

  {
    title: "SOC Copilot",
    description:
      "Ask cybersecurity questions using the RAG-powered analyst assistant.",
    route: "/analyst",
    category: "Artificial Intelligence",
  },

  {
    title: "Threat Intelligence",
    description:
      "Enrich IOCs using AbuseIPDB, VirusTotal, OTX and MISP.",
    route: "/threat-intelligence",
    category: "Threat Intelligence",
  },

  {
    title: "MITRE ATT&CK",
    description:
      "Validate ATT&CK techniques and inspect technique information.",
    route: "/mitre",
    category: "Knowledge Base",
  },

  {
    title: "Machine Learning",
    description:
      "Run network classification and Suricata anomaly detection.",
    route: "/ml",
    category: "Machine Learning",
  },

  {
    title: "SOAR Actions",
    description:
      "Review, approve and execute automated response actions.",
    route: "/soar",
    category: "Response",
  },

  {
    title: "SOC Reports",
    description:
      "Review generated reports, AI results, ML context and recommendations.",
    route: "/reports",
    category: "Reporting",
  },

  {
    title: "User Administration",
    description:
      "Manage SOC users, roles, account status and credentials through Keycloak.",
    route: "/admin/users",
    category: "Administration",
    adminOnly: true,
  },
];


// =====================================================
// HELPERS
// =====================================================

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


function severityClass(
  severity?: string | null
) {
  switch (
    normalize(severity)
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
  status?: string | null
) {
  switch (
    normalize(status)
  ) {
    case "resolved":
    case "closed":
      return (
        "border-emerald-500/40 " +
        "bg-emerald-500/10 " +
        "text-emerald-400"
      );

    case "investigating":
    case "in_progress":
      return (
        "border-violet-500/40 " +
        "bg-violet-500/10 " +
        "text-violet-300"
      );

    case "open":
    case "new":
      return (
        "border-cyan-500/40 " +
        "bg-cyan-500/10 " +
        "text-cyan-300"
      );

    default:
      return (
        "border-slate-500/40 " +
        "bg-slate-500/10 " +
        "text-slate-300"
      );
  }
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


// =====================================================
// PAGE
// =====================================================

export default function DashboardPage() {
  const router =
    useRouter();


  const [
    metrics,
    setMetrics,
  ] =
    useState<Metrics | null>(
      null
    );


  const [
    severity,
    setSeverity,
  ] =
    useState<SeverityMetric[]>(
      []
    );


  const [
    incidents,
    setIncidents,
  ] =
    useState<Incident[]>(
      []
    );


  const [
    roles,
    setRoles,
  ] =
    useState<string[]>(
      []
    );


  const [
    loading,
    setLoading,
  ] =
    useState(true);


  const [
    refreshing,
    setRefreshing,
  ] =
    useState(false);


  const [
    error,
    setError,
  ] =
    useState<string | null>(
      null
    );


  const isAdmin =
    roles.includes(
      "admin"
    );


  // =====================================================
  // REFRESH DASHBOARD
  // =====================================================

  const loadDashboard =
    useCallback(
      async () => {
        try {
          setRefreshing(
            true
          );

          setError(
            null
          );


          const authenticated =
            await initKeycloak();


          if (
            !authenticated
          ) {
            router.replace(
              "/login"
            );

            return;
          }


          const currentRoles =
            getCurrentRoles();


          const [
            metricsData,
            severityData,
            incidentsData,
          ] =
            await Promise.all([
              apiRequest<Metrics>(
                "/metrics"
              ),

              apiRequest<
                SeverityMetricsResponse
              >(
                "/metrics/severity"
              ),

              apiRequest<
                Incident[]
              >(
                "/incidents"
              ),
            ]);


          setRoles(
            currentRoles
          );


          setMetrics(
            metricsData
          );


          if (
            Array.isArray(
              severityData
            )
          ) {
            setSeverity(
              severityData
            );

          } else {
            setSeverity(
              Object.entries(
                severityData
              ).map(
                ([
                  severityName,
                  count,
                ]) => ({
                  severity:
                    severityName,

                  count:
                    Number(
                      count
                    ),
                })
              )
            );
          }


          setIncidents(
            incidentsData.slice(
              0,
              6
            )
          );

        } catch (
          requestError
        ) {
          console.error(
            "Dashboard loading error:",
            requestError
          );

          setError(
            requestError instanceof Error
              ? requestError.message
              : "Unable to load dashboard"
          );

        } finally {
          setRefreshing(
            false
          );
        }
      },
      [
        router,
      ]
    );


  // =====================================================
  // INITIAL LOAD
  // =====================================================

  useEffect(() => {
    let active =
      true;


    async function initializeDashboard() {
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


        const currentRoles =
          getCurrentRoles();


        const [
          metricsData,
          severityData,
          incidentsData,
        ] =
          await Promise.all([
            apiRequest<Metrics>(
              "/metrics"
            ),

            apiRequest<
              SeverityMetricsResponse
            >(
              "/metrics/severity"
            ),

            apiRequest<
              Incident[]
            >(
              "/incidents"
            ),
          ]);


        if (
          !active
        ) {
          return;
        }


        setRoles(
          currentRoles
        );


        setMetrics(
          metricsData
        );


        if (
          Array.isArray(
            severityData
          )
        ) {
          setSeverity(
            severityData
          );

        } else {
          setSeverity(
            Object.entries(
              severityData
            ).map(
              ([
                severityName,
                count,
              ]) => ({
                severity:
                  severityName,

                count:
                  Number(
                    count
                  ),
              })
            )
          );
        }


        setIncidents(
          incidentsData.slice(
            0,
            6
          )
        );

      } catch (
        requestError
      ) {
        console.error(
          "Dashboard loading error:",
          requestError
        );


        if (
          active
        ) {
          setError(
            requestError instanceof Error
              ? requestError.message
              : "Unable to load dashboard"
          );
        }

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


    void initializeDashboard();


    return () => {
      active =
        false;
    };

  }, [
    router,
  ]);


  // =====================================================
  // SORT SEVERITY
  // =====================================================

  const sortedSeverity =
    useMemo(
      () => {
        const priority:
          Record<
            string,
            number
          > = {
          critical: 0,
          high: 1,
          medium: 2,
          low: 3,
        };


        return [
          ...severity,
        ].sort(
          (
            first,
            second
          ) =>
            (
              priority[
                normalize(
                  first.severity
                )
              ]
              ?? 99
            )
            -
            (
              priority[
                normalize(
                  second.severity
                )
              ]
              ?? 99
            )
        );
      },
      [
        severity,
      ]
    );


  // =====================================================
  // LOADING
  // =====================================================

  if (
    loading
  ) {
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
            rounded-xl
            border
            border-slate-700
            bg-[#0b1622]
            p-8
          "
        >
          Loading SOC dashboard...
        </div>
      </main>
    );
  }


  // =====================================================
  // PAGE
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
          max-w-[1750px]
          space-y-7
        "
      >

        {/* HEADER */}

        <section
          className="
            flex
            flex-col
            gap-5
            xl:flex-row
            xl:items-center
            xl:justify-between
          "
        >
          <div>
            <p
              className="
                text-sm
                uppercase
                tracking-[0.30em]
                text-cyan-400
              "
            >
              Security Operations Center
            </p>


            <h1
              className="
                mt-2
                text-4xl
                font-bold
              "
            >
              SOC Dashboard
            </h1>


            <p
              className="
                mt-2
                max-w-3xl
                text-slate-400
              "
            >
              Unified monitoring, investigation,
              artificial intelligence, threat
              intelligence, automation and reporting
              workspace.
            </p>
          </div>


          <button
            type="button"
            disabled={
              refreshing
            }
            onClick={
              () =>
                void loadDashboard()
            }
            className="
              rounded-lg
              bg-cyan-500
              px-5
              py-3
              font-semibold
              text-slate-950
              transition
              hover:bg-cyan-400
              disabled:opacity-50
            "
          >
            {
              refreshing
                ? "Refreshing..."
                : "Refresh Dashboard"
            }
          </button>
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


        {/* KPIS */}

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
              p-6
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
                text-4xl
                font-bold
              "
            >
              {
                metrics
                  ?.total_incidents
                ?? 0
              }
            </p>
          </div>


          <div
            className="
              rounded-xl
              border
              border-cyan-500/30
              bg-[#0b1622]
              p-6
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
              Open Incidents
            </p>


            <p
              className="
                mt-3
                text-4xl
                font-bold
                text-cyan-300
              "
            >
              {
                metrics
                  ?.open_incidents
                ?? 0
              }
            </p>
          </div>


          <div
            className="
              rounded-xl
              border
              border-red-500/30
              bg-[#0b1622]
              p-6
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
                text-4xl
                font-bold
                text-red-400
              "
            >
              {
                metrics
                  ?.critical_incidents
                ?? 0
              }
            </p>
          </div>


          <div
            className="
              rounded-xl
              border
              border-emerald-500/30
              bg-[#0b1622]
              p-6
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
              Resolved
            </p>


            <p
              className="
                mt-3
                text-4xl
                font-bold
                text-emerald-400
              "
            >
              {
                metrics
                  ?.resolved_incidents
                ?? 0
              }
            </p>
          </div>
        </section>


        {/* SOC MODULES */}

        <section>
          <div
            className="
              mb-4
              flex
              items-end
              justify-between
              gap-4
            "
          >
            <div>
              <p
                className="
                  text-sm
                  uppercase
                  tracking-[0.20em]
                  text-cyan-400
                "
              >
                SOC Workspace
              </p>


              <h2
                className="
                  mt-1
                  text-2xl
                  font-bold
                "
              >
                Security Modules
              </h2>
            </div>
          </div>


          <div
            className="
              grid
              gap-4
              md:grid-cols-2
              xl:grid-cols-4
            "
          >
            {
              navigationItems
                .filter(
                  (item) =>
                    !item.adminOnly
                    || isAdmin
                )
                .map(
                  (item) => (
                    <button
                      key={
                        item.route
                      }
                      type="button"
                      onClick={
                        () =>
                          router.push(
                            item.route
                          )
                      }
                      className="
                        group
                        rounded-xl
                        border
                        border-slate-700
                        bg-[#0b1622]
                        p-5
                        text-left
                        transition
                        hover:-translate-y-0.5
                        hover:border-cyan-500/60
                        hover:bg-[#0d1a28]
                      "
                    >
                      <p
                        className="
                          text-xs
                          uppercase
                          tracking-wider
                          text-cyan-400
                        "
                      >
                        {
                          item.category
                        }
                      </p>


                      <h3
                        className="
                          mt-3
                          text-xl
                          font-bold
                          text-slate-100
                          group-hover:text-cyan-300
                        "
                      >
                        {
                          item.title
                        }
                      </h3>


                      <p
                        className="
                          mt-3
                          text-sm
                          leading-6
                          text-slate-400
                        "
                      >
                        {
                          item.description
                        }
                      </p>


                      <p
                        className="
                          mt-5
                          text-sm
                          font-medium
                          text-cyan-300
                        "
                      >
                        Open module →
                      </p>
                    </button>
                  )
                )
            }
          </div>
        </section>


        {/* SEVERITY + INCIDENTS */}

        <section
          className="
            grid
            gap-5
            xl:grid-cols-[0.8fr_1.8fr]
          "
        >

          {/* SEVERITY */}

          <div
            className="
              rounded-xl
              border
              border-slate-700
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
              Incident Severity
            </h2>


            <p
              className="
                mt-1
                text-sm
                text-slate-400
              "
            >
              Current incident distribution.
            </p>


            <div
              className="
                mt-6
                space-y-3
              "
            >
              {
                sortedSeverity.length >
                0 ? (
                  sortedSeverity.map(
                    (item) => (
                      <div
                        key={
                          item.severity
                        }
                        className="
                          flex
                          items-center
                          justify-between
                          rounded-lg
                          border
                          border-slate-800
                          bg-[#07111c]
                          p-4
                        "
                      >
                        <span
                          className={[
                            "rounded-full",
                            "border",
                            "px-3",
                            "py-1",
                            "text-sm",
                            "font-medium",
                            severityClass(
                              item.severity
                            ),
                          ].join(
                            " "
                          )}
                        >
                          {
                            item.severity
                          }
                        </span>


                        <strong
                          className="
                            text-xl
                          "
                        >
                          {
                            item.count
                          }
                        </strong>
                      </div>
                    )
                  )
                ) : (
                  <p
                    className="
                      text-sm
                      text-slate-500
                    "
                  >
                    No severity data available.
                  </p>
                )
              }
            </div>
          </div>


          {/* RECENT INCIDENTS */}

          <div
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
                flex
                items-center
                justify-between
                border-b
                border-slate-700
                p-6
              "
            >
              <div>
                <h2
                  className="
                    text-xl
                    font-bold
                  "
                >
                  Recent Incidents
                </h2>


                <p
                  className="
                    mt-1
                    text-sm
                    text-slate-400
                  "
                >
                  Latest incidents received
                  by the SOC.
                </p>
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
                View All
              </button>
            </div>


            <div
              className="
                divide-y
                divide-slate-800
              "
            >
              {
                incidents.length >
                0 ? (
                  incidents.map(
                    (incident) => (
                      <button
                        key={
                          incident.id
                        }
                        type="button"
                        onClick={
                          () =>
                            router.push(
                              `/incidents/${incident.id}`
                            )
                        }
                        className="
                          flex
                          w-full
                          flex-col
                          gap-4
                          p-5
                          text-left
                          transition
                          hover:bg-slate-800/40
                          md:flex-row
                          md:items-center
                          md:justify-between
                        "
                      >
                        <div
                          className="
                            min-w-0
                          "
                        >
                          <p
                            className="
                              font-mono
                              text-sm
                              text-cyan-300
                            "
                          >
                            Incident #
                            {
                              incident.id
                            }
                          </p>


                          <p
                            className="
                              mt-1
                              truncate
                              font-semibold
                              text-slate-100
                            "
                          >
                            {
                              incident.title
                            }
                          </p>


                          <p
                            className="
                              mt-1
                              text-sm
                              text-slate-400
                            "
                          >
                            Source:{" "}
                            {
                              incident.source
                            }
                          </p>
                        </div>


                        <div
                          className="
                            flex
                            flex-wrap
                            gap-2
                          "
                        >
                          <span
                            className={[
                              "rounded-full",
                              "border",
                              "px-3",
                              "py-1",
                              "text-xs",
                              severityClass(
                                incident.severity
                              ),
                            ].join(
                              " "
                            )}
                          >
                            {
                              incident.severity
                            }
                          </span>


                          <span
                            className={[
                              "rounded-full",
                              "border",
                              "px-3",
                              "py-1",
                              "text-xs",
                              statusClass(
                                incident.status
                              ),
                            ].join(
                              " "
                            )}
                          >
                            {
                              incident.status
                            }
                          </span>
                        </div>
                      </button>
                    )
                  )
                ) : (
                  <div
                    className="
                      p-10
                      text-center
                      text-slate-400
                    "
                  >
                    No incidents available.
                  </div>
                )
              }
            </div>
          </div>
        </section>


        {/* ARCHITECTURE SUMMARY */}

        <section
          className="
            grid
            gap-4
            md:grid-cols-3
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
                text-slate-500
              "
            >
              Detection
            </p>


            <p
              className="
                mt-2
                font-semibold
              "
            >
              Wazuh + Suricata
            </p>
          </div>


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
                text-slate-500
              "
            >
              Intelligence
            </p>


            <p
              className="
                mt-2
                font-semibold
              "
            >
              LLM + RAG + ML + Threat Intel
            </p>
          </div>


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
                text-slate-500
              "
            >
              Response
            </p>


            <p
              className="
                mt-2
                font-semibold
              "
            >
              HITL + SOAR Automation
            </p>
          </div>
        </section>

      </div>
    </main>
  );
}