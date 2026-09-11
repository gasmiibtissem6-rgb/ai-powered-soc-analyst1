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


type Alert = {
  id: number;
  title: string;
  description?: string | null;
  severity: string;
  source: string;
  status: string;
  created_at: string;
};


type AlertCreate = {
  title: string;
  description?: string;
  severity: string;
  source: string;
};


type AlertUpdate = {
  title?: string;
  description?: string;
  severity?: string;
  source?: string;
  status?: string;
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

  preferred_username?: string;
};


type Filters = {
  search: string;
  severity: string;
  status: string;
  source: string;
};


const initialFilters: Filters = {
  search: "",
  severity: "all",
  status: "all",
  source: "all",
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
    case "new":
      return (
        "border-cyan-500/40 " +
        "bg-cyan-500/10 " +
        "text-cyan-300"
      );

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


export default function AlertsPage() {
  const router =
    useRouter();


  const [alerts, setAlerts] =
    useState<Alert[]>([]);


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
    createOpen,
    setCreateOpen,
  ] =
    useState(false);


  const [
    createLoading,
    setCreateLoading,
  ] =
    useState(false);


  const [
    actionLoading,
    setActionLoading,
  ] =
    useState<number | null>(
      null
    );


  const [
    newTitle,
    setNewTitle,
  ] =
    useState("");


  const [
    newDescription,
    setNewDescription,
  ] =
    useState("");


  const [
    newSeverity,
    setNewSeverity,
  ] =
    useState("medium");


  const [
    newSource,
    setNewSource,
  ] =
    useState("manual");


  // =====================================================
  // INITIAL LOAD
  // =====================================================

  useEffect(() => {
    let active =
      true;

    async function loadInitialAlerts() {
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
            Alert[]
          >(
            "/alerts"
          );

        if (!active) {
          return;
        }

        setRoles(
          currentRoles
        );

        setAlerts(
          data
        );

      } catch (requestError) {
        console.error(
          "Unable to load alerts:",
          requestError
        );

        if (!active) {
          return;
        }

        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to load alerts"
        );

      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    void loadInitialAlerts();

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

  async function refreshAlerts() {
    try {
      setRefreshing(
        true
      );

      setError(
        null
      );

      const data =
        await apiRequest<
          Alert[]
        >(
          "/alerts"
        );

      setAlerts(
        data
      );

    } catch (requestError) {
      console.error(
        "Unable to refresh alerts:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to refresh alerts"
      );

    } finally {
      setRefreshing(
        false
      );
    }
  }


  // =====================================================
  // CREATE ALERT
  // =====================================================

  async function createAlert() {
    const title =
      newTitle.trim();

    const source =
      newSource.trim();

    if (!title) {
      setError(
        "Alert title is required."
      );

      return;
    }

    if (!source) {
      setError(
        "Alert source is required."
      );

      return;
    }

    const payload: AlertCreate = {
      title,
      severity:
        newSeverity,
      source,
    };

    const description =
      newDescription.trim();

    if (description) {
      payload.description =
        description;
    }

    try {
      setCreateLoading(
        true
      );

      setError(
        null
      );

      const created =
        await apiRequest<
          Alert
        >(
          "/alerts",
          {
            method: "POST",

            body:
              JSON.stringify(
                payload
              ),
          }
        );

      setAlerts(
        (current) => [
          created,
          ...current,
        ]
      );

      setNewTitle(
        ""
      );

      setNewDescription(
        ""
      );

      setNewSeverity(
        "medium"
      );

      setNewSource(
        "manual"
      );

      setCreateOpen(
        false
      );

    } catch (requestError) {
      console.error(
        "Unable to create alert:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to create alert"
      );

    } finally {
      setCreateLoading(
        false
      );
    }
  }


  // =====================================================
  // UPDATE ALERT
  // =====================================================

  async function updateAlert(
    alert: Alert,
    payload: AlertUpdate
  ) {
    try {
      setActionLoading(
        alert.id
      );

      setError(
        null
      );

      const updated =
        await apiRequest<
          Alert
        >(
          `/alerts/${alert.id}`,
          {
            method: "PUT",

            body:
              JSON.stringify(
                payload
              ),
          }
        );

      setAlerts(
        (current) =>
          current.map(
            (item) =>
              item.id ===
              updated.id
                ? updated
                : item
          )
      );

    } catch (requestError) {
      console.error(
        "Unable to update alert:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to update alert"
      );

    } finally {
      setActionLoading(
        null
      );
    }
  }


  // =====================================================
  // DELETE ALERT
  // =====================================================

  async function deleteAlert(
    alert: Alert
  ) {
    if (!isAdmin) {
      setError(
        "Administrator privileges are required to delete alerts."
      );

      return;
    }

    const confirmed =
      window.confirm(
        `Delete alert #${alert.id}?`
      );

    if (!confirmed) {
      return;
    }

    try {
      setActionLoading(
        alert.id
      );

      setError(
        null
      );

      await apiRequest<void>(
        `/alerts/${alert.id}`,
        {
          method: "DELETE",
        }
      );

      setAlerts(
        (current) =>
          current.filter(
            (item) =>
              item.id !==
              alert.id
          )
      );

    } catch (requestError) {
      console.error(
        "Unable to delete alert:",
        requestError
      );

      if (
        requestError instanceof ApiError &&
        requestError.status === 403
      ) {
        setError(
          "Administrator privileges are required to delete this alert."
        );

      } else {
        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to delete alert"
        );
      }

    } finally {
      setActionLoading(
        null
      );
    }
  }


  // =====================================================
  // FILTER OPTIONS
  // =====================================================

  const severities =
    useMemo(
      () =>
        Array.from(
          new Set(
            alerts
              .map(
                (alert) =>
                  alert.severity
              )
              .filter(Boolean)
          )
        ).sort(),
      [alerts]
    );


  const statuses =
    useMemo(
      () =>
        Array.from(
          new Set(
            alerts
              .map(
                (alert) =>
                  alert.status
              )
              .filter(Boolean)
          )
        ).sort(),
      [alerts]
    );


  const sources =
    useMemo(
      () =>
        Array.from(
          new Set(
            alerts
              .map(
                (alert) =>
                  alert.source
              )
              .filter(Boolean)
          )
        ).sort(),
      [alerts]
    );


  // =====================================================
  // FILTER RESULTS
  // =====================================================

  const filteredAlerts =
    useMemo(() => {
      const search =
        normalize(
          filters.search
        );

      return alerts.filter(
        (alert) => {
          const matchesSearch =
            !search ||
            [
              String(
                alert.id
              ),
              alert.title,
              alert.description,
              alert.source,
              alert.severity,
              alert.status,
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
              alert.severity
            ) ===
              normalize(
                filters.severity
              );

          const matchesStatus =
            filters.status === "all" ||
            normalize(
              alert.status
            ) ===
              normalize(
                filters.status
              );

          const matchesSource =
            filters.source === "all" ||
            normalize(
              alert.source
            ) ===
              normalize(
                filters.source
              );

          return (
            matchesSearch &&
            matchesSeverity &&
            matchesStatus &&
            matchesSource
          );
        }
      );

    }, [
      alerts,
      filters,
    ]);


  // =====================================================
  // KPI
  // =====================================================

  const totals =
    useMemo(
      () => ({
        total:
          alerts.length,

        critical:
          alerts.filter(
            (alert) =>
              normalize(
                alert.severity
              ) === "critical"
          ).length,

        high:
          alerts.filter(
            (alert) =>
              normalize(
                alert.severity
              ) === "high"
          ).length,

        open:
          alerts.filter(
            (alert) =>
              [
                "open",
                "new",
                "investigating",
                "in_progress",
              ].includes(
                normalize(
                  alert.status
                )
              )
          ).length,
      }),
      [alerts]
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
          Loading alerts...
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
              Security Event Monitoring
            </p>

            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              Alerts
            </h1>

            <p
              className="
                mt-2
                text-sm
                text-slate-400
              "
            >
              Review and manage security alerts
              received by the SOC.
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
              onClick={
                () =>
                  setCreateOpen(
                    (current) =>
                      !current
                  )
              }
              className="
                rounded-lg
                border
                border-cyan-500/50
                px-4
                py-2
                text-sm
                text-cyan-300
                hover:bg-cyan-500/10
              "
            >
              New Alert
            </button>


            <button
              type="button"
              disabled={
                refreshing
              }
              onClick={
                () =>
                  void refreshAlerts()
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


        {/* CREATE ALERT */}

        {
          createOpen && (
            <section
              className="
                rounded-xl
                border
                border-cyan-500/30
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
                Create Alert
              </h2>


              <div
                className="
                  mt-5
                  grid
                  gap-4
                  md:grid-cols-2
                  xl:grid-cols-4
                "
              >
                <input
                  value={
                    newTitle
                  }
                  onChange={
                    (event) =>
                      setNewTitle(
                        event.target.value
                      )
                  }
                  placeholder="Alert title"
                  className="
                    rounded-lg
                    border
                    border-slate-600
                    bg-[#07111c]
                    px-3
                    py-3
                    outline-none
                    focus:border-cyan-500
                  "
                />


                <select
                  value={
                    newSeverity
                  }
                  onChange={
                    (event) =>
                      setNewSeverity(
                        event.target.value
                      )
                  }
                  className="
                    rounded-lg
                    border
                    border-slate-600
                    bg-[#07111c]
                    px-3
                    py-3
                  "
                >
                  <option value="low">
                    Low
                  </option>

                  <option value="medium">
                    Medium
                  </option>

                  <option value="high">
                    High
                  </option>

                  <option value="critical">
                    Critical
                  </option>
                </select>


                <input
                  value={
                    newSource
                  }
                  onChange={
                    (event) =>
                      setNewSource(
                        event.target.value
                      )
                  }
                  placeholder="Source"
                  className="
                    rounded-lg
                    border
                    border-slate-600
                    bg-[#07111c]
                    px-3
                    py-3
                    outline-none
                    focus:border-cyan-500
                  "
                />


                <button
                  type="button"
                  disabled={
                    createLoading
                  }
                  onClick={
                    () =>
                      void createAlert()
                  }
                  className="
                    rounded-lg
                    bg-cyan-500
                    px-4
                    py-3
                    font-semibold
                    text-slate-950
                    hover:bg-cyan-400
                    disabled:opacity-50
                  "
                >
                  {
                    createLoading
                      ? "Creating..."
                      : "Create Alert"
                  }
                </button>
              </div>


              <textarea
                value={
                  newDescription
                }
                onChange={
                  (event) =>
                    setNewDescription(
                      event.target.value
                    )
                }
                placeholder="Description"
                className="
                  mt-4
                  min-h-[110px]
                  w-full
                  rounded-lg
                  border
                  border-slate-600
                  bg-[#07111c]
                  p-3
                  outline-none
                  focus:border-cyan-500
                "
              />
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
              Total Alerts
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
              border-cyan-500/30
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
              Active
            </p>

            <p
              className="
                mt-3
                text-3xl
                font-bold
                text-cyan-300
              "
            >
              {totals.open}
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
              placeholder="Search ID, title, source..."
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
                  filteredAlerts.length
                }
              </strong>{" "}
              of{" "}
              <strong
                className="
                  text-slate-100
                "
              >
                {
                  alerts.length
                }
              </strong>{" "}
              alerts
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


        {/* ALERT TABLE */}

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
                  <th
                    className="
                      w-[80px]
                      px-4
                      py-4
                    "
                  >
                    ID
                  </th>

                  <th
                    className="
                      w-[500px]
                      px-4
                      py-4
                    "
                  >
                    Alert
                  </th>

                  <th
                    className="
                      w-[150px]
                      px-4
                      py-4
                    "
                  >
                    Severity
                  </th>

                  <th
                    className="
                      w-[130px]
                      px-4
                      py-4
                    "
                  >
                    Source
                  </th>

                  <th
                    className="
                      w-[180px]
                      px-4
                      py-4
                    "
                  >
                    Status
                  </th>

                  <th
                    className="
                      w-[210px]
                      px-4
                      py-4
                    "
                  >
                    Created
                  </th>

                  <th
                    className="
                      w-[130px]
                      px-4
                      py-4
                    "
                  >
                    Operations
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
                  filteredAlerts.map(
                    (alert) => {
                      const busy =
                        actionLoading ===
                        alert.id;

                      return (
                        <tr
                          key={
                            alert.id
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
                            #{alert.id}
                          </td>


                          <td
                            className="
                              w-[500px]
                              max-w-[500px]
                              px-4
                              py-4
                            "
                          >
                            <p
                              title={
                                alert.title
                              }
                              className="
                                truncate
                                font-semibold
                                text-slate-100
                              "
                            >
                              {alert.title}
                            </p>

                            {
                              alert.description && (
                                <p
                                  title={
                                    alert.description
                                  }
                                  className="
                                    mt-1
                                    line-clamp-2
                                    max-w-[470px]
                                    overflow-hidden
                                    break-words
                                    text-sm
                                    text-slate-400
                                  "
                                >
                                  {
                                    alert.description
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
                            <select
                              value={
                                alert.severity
                              }
                              disabled={
                                busy
                              }
                              onChange={
                                (event) =>
                                  void updateAlert(
                                    alert,
                                    {
                                      severity:
                                        event.target.value,
                                    }
                                  )
                              }
                              className="
                                w-full
                                rounded-lg
                                border
                                border-slate-600
                                bg-[#07111c]
                                px-2
                                py-1.5
                                text-sm
                              "
                            >
                              <option value="low">
                                low
                              </option>

                              <option value="medium">
                                medium
                              </option>

                              <option value="high">
                                high
                              </option>

                              <option value="critical">
                                critical
                              </option>
                            </select>
                          </td>


                          <td
                            title={
                              alert.source
                            }
                            className="
                              truncate
                              px-4
                              py-4
                              text-sm
                              text-slate-300
                            "
                          >
                            {
                              alert.source
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
                                mb-2
                              "
                            >
                              <Badge
                                value={
                                  alert.status
                                }
                              />
                            </div>

                            <select
                              value={
                                alert.status
                              }
                              disabled={
                                busy
                              }
                              onChange={
                                (event) =>
                                  void updateAlert(
                                    alert,
                                    {
                                      status:
                                        event.target.value,
                                    }
                                  )
                              }
                              className="
                                w-full
                                rounded-lg
                                border
                                border-slate-600
                                bg-[#07111c]
                                px-2
                                py-1.5
                                text-sm
                              "
                            >
                              <option value="open">
                                open
                              </option>

                              <option value="investigating">
                                investigating
                              </option>

                              <option value="resolved">
                                resolved
                              </option>

                              <option value="closed">
                                closed
                              </option>
                            </select>
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
                                alert.created_at
                              )
                            }
                          </td>


                          <td
                            className="
                              px-4
                              py-4
                            "
                          >
                            {
                              isAdmin ? (
                                <button
                                  type="button"
                                  disabled={
                                    busy
                                  }
                                  onClick={
                                    () =>
                                      void deleteAlert(
                                        alert
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
                                    busy
                                      ? "Processing..."
                                      : "Delete"
                                  }
                                </button>
                              ) : (
                                <span
                                  className="
                                    text-xs
                                    text-slate-500
                                  "
                                >
                                  Analyst access
                                </span>
                              )
                            }
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
            filteredAlerts.length === 0 && (
              <div
                className="
                  p-10
                  text-center
                  text-slate-400
                "
              >
                No alerts match the current filters.
              </div>
            )
          }
        </section>

      </div>
    </main>
  );
}