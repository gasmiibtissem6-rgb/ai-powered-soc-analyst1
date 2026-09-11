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


type SOARAction = {
  id: number;
  incident_id: number;

  action_type: string;
  target: string;

  status: string;

  requires_approval: boolean;
  approved?: boolean | null;

  result?: unknown;

  executed_at?: string | null;
  created_at: string;
};


type SOARActionLog = {
  id: number;
  action_id: number;
  incident_id: number;

  event_type: string;

  previous_status?: string | null;
  new_status: string;

  details?: unknown;

  created_at: string;
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


type ActionOperation =
  | "approve"
  | "reject"
  | "execute";


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


function statusClass(
  status?: string | null
) {
  switch (
    normalize(status)
  ) {
    case "approved":
      return (
        "border-cyan-500/40 " +
        "bg-cyan-500/10 " +
        "text-cyan-300"
      );

    case "pending":
      return (
        "border-yellow-500/40 " +
        "bg-yellow-500/10 " +
        "text-yellow-300"
      );

    case "executed":
    case "completed":
      return (
        "border-emerald-500/40 " +
        "bg-emerald-500/10 " +
        "text-emerald-400"
      );

    case "simulated":
      return (
        "border-violet-500/40 " +
        "bg-violet-500/10 " +
        "text-violet-300"
      );

    case "rejected":
    case "execution_failed":
    case "blocked_by_safety":
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


export default function SOARPage() {

  const router =
    useRouter();


  const [actions, setActions] =
    useState<SOARAction[]>([]);


  const [loading, setLoading] =
    useState(true);


  const [refreshing, setRefreshing] =
    useState(false);


  const [error, setError] =
    useState<string | null>(
      null
    );


  const [search, setSearch] =
    useState("");


  const [statusFilter, setStatusFilter] =
    useState("all");


  const [
    actionTypeFilter,
    setActionTypeFilter,
  ] =
    useState("all");


  const [
    selectedAction,
    setSelectedAction,
  ] =
    useState<SOARAction | null>(
      null
    );


  const [
    selectedLogs,
    setSelectedLogs,
  ] =
    useState<SOARActionLog[]>([]);


  const [
    logsLoading,
    setLogsLoading,
  ] =
    useState(false);


  const [
    operationLoading,
    setOperationLoading,
  ] =
    useState<number | null>(
      null
    );


  const [roles, setRoles] =
    useState<string[]>([]);


  // =====================================================
  // INITIAL LOAD
  // =====================================================

  useEffect(() => {

    let active =
      true;


    async function loadInitialData() {

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
            SOARAction[]
          >(
            "/soar"
          );


        if (!active) {
          return;
        }


        setRoles(
          currentRoles
        );


        setActions(
          data
        );


      } catch (requestError) {

        console.error(
          "Unable to load SOAR actions:",
          requestError
        );


        if (!active) {
          return;
        }


        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to load SOAR actions"
        );


      } finally {

        if (active) {
          setLoading(false);
        }

      }

    }


    void loadInitialData();


    return () => {

      active =
        false;

    };

  }, [router]);


  // =====================================================
  // RBAC
  // =====================================================

  const isAdmin =
    roles.includes(
      "admin"
    );


  // =====================================================
  // REFRESH
  // =====================================================

  async function refreshActions() {

    try {

      setRefreshing(true);
      setError(null);


      const data =
        await apiRequest<
          SOARAction[]
        >(
          "/soar"
        );


      setActions(
        data
      );


      if (selectedAction) {

        const updated =
          data.find(
            (action) =>
              action.id ===
              selectedAction.id
          );


        if (updated) {

          setSelectedAction(
            updated
          );

        }

      }


    } catch (requestError) {

      console.error(
        "Unable to refresh SOAR actions:",
        requestError
      );


      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to refresh SOAR actions"
      );


    } finally {

      setRefreshing(false);

    }

  }


  // =====================================================
  // LOAD AUDIT LOGS
  // =====================================================

  async function loadLogs(
    action: SOARAction
  ) {

    try {

      setSelectedAction(
        action
      );


      setLogsLoading(
        true
      );


      setSelectedLogs(
        []
      );


      const data =
        await apiRequest<
          SOARActionLog[]
        >(
          `/soar/${action.id}/logs`
        );


      setSelectedLogs(
        data
      );


    } catch (requestError) {

      console.error(
        "Unable to load SOAR audit logs:",
        requestError
      );


      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to load SOAR logs"
      );


    } finally {

      setLogsLoading(
        false
      );

    }

  }


  // =====================================================
  // APPROVE / REJECT / EXECUTE
  // =====================================================

  async function runOperation(
    action: SOARAction,
    operation: ActionOperation
  ) {

    if (!isAdmin) {

      setError(
        "Administrator privileges are required for this SOAR operation."
      );

      return;
    }


    try {

      setOperationLoading(
        action.id
      );


      setError(
        null
      );


      const updated =
        await apiRequest<
          SOARAction
        >(
          `/soar/${action.id}/${operation}`,
          {
            method: "POST",
          }
        );


      setActions(
        (current) =>
          current.map(
            (item) =>
              item.id ===
              updated.id
                ? updated
                : item
          )
      );


      setSelectedAction(
        updated
      );


      const logs =
        await apiRequest<
          SOARActionLog[]
        >(
          `/soar/${updated.id}/logs`
        );


      setSelectedLogs(
        logs
      );


    } catch (requestError) {

      console.error(
        `Unable to ${operation} SOAR action:`,
        requestError
      );


      if (
        requestError instanceof ApiError
      ) {

        if (
          requestError.status === 403
        ) {

          setError(
            requestError.message ||
              "Insufficient permissions"
          );

        } else {

          setError(
            requestError.message
          );

        }

      } else {

        setError(
          requestError instanceof Error
            ? requestError.message
            : `Unable to ${operation} SOAR action`
        );

      }


    } finally {

      setOperationLoading(
        null
      );

    }

  }


  // =====================================================
  // FILTER OPTIONS
  // =====================================================

  const statuses =
    useMemo(
      () =>
        Array.from(
          new Set(
            actions
              .map(
                (action) =>
                  action.status
              )
              .filter(Boolean)
          )
        ).sort(),
      [actions]
    );


  const actionTypes =
    useMemo(
      () =>
        Array.from(
          new Set(
            actions
              .map(
                (action) =>
                  action.action_type
              )
              .filter(Boolean)
          )
        ).sort(),
      [actions]
    );


  // =====================================================
  // FILTERED ACTIONS
  // =====================================================

  const filteredActions =
    useMemo(() => {

      const normalizedSearch =
        normalize(
          search
        );


      return actions.filter(
        (action) => {

          const matchesSearch =
            !normalizedSearch ||
            [
              String(
                action.id
              ),
              String(
                action.incident_id
              ),
              action.action_type,
              action.target,
              action.status,
            ].some(
              (value) =>
                normalize(
                  value
                ).includes(
                  normalizedSearch
                )
            );


          const matchesStatus =
            statusFilter === "all" ||
            normalize(
              action.status
            ) ===
              normalize(
                statusFilter
              );


          const matchesType =
            actionTypeFilter === "all" ||
            normalize(
              action.action_type
            ) ===
              normalize(
                actionTypeFilter
              );


          return (
            matchesSearch &&
            matchesStatus &&
            matchesType
          );

        }
      );

    }, [
      actions,
      search,
      statusFilter,
      actionTypeFilter,
    ]);


  // =====================================================
  // COUNTERS
  // =====================================================

  const totals =
    useMemo(
      () => ({
        total:
          actions.length,

        pending:
          actions.filter(
            (action) =>
              normalize(
                action.status
              ) === "pending"
          ).length,

        simulated:
          actions.filter(
            (action) =>
              normalize(
                action.status
              ) === "simulated"
          ).length,

        executed:
          actions.filter(
            (action) =>
              normalize(
                action.status
              ) === "executed"
          ).length,

        blocked:
          actions.filter(
            (action) =>
              normalize(
                action.status
              ) ===
              "blocked_by_safety"
          ).length,
      }),
      [actions]
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
          Loading SOAR actions...
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
              Security Orchestration,
              Automation and Response
            </p>


            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              SOAR Actions
            </h1>


            <p
              className="
                mt-2
                text-sm
                text-slate-400
              "
            >
              Review, approve and execute
              SOC response actions.
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
              disabled={
                refreshing
              }
              onClick={
                () =>
                  void refreshActions()
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


        {/* DRY RUN INFORMATION */}

        <section
          className="
            rounded-xl
            border
            border-violet-500/30
            bg-violet-500/5
            p-4
            text-sm
            text-violet-200
          "
        >
          SOAR safety mode is configured by
          the backend. When execution mode is
          <strong> dry_run</strong>, response
          actions are simulated and no
          destructive infrastructure change
          is performed.
        </section>


        {/* KPIs */}

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
              Total Actions
            </p>

            <p className="mt-3 text-3xl font-bold">
              {totals.total}
            </p>
          </div>


          <div className="rounded-xl border border-yellow-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Pending
            </p>

            <p className="mt-3 text-3xl font-bold text-yellow-300">
              {totals.pending}
            </p>
          </div>


          <div className="rounded-xl border border-violet-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Simulated
            </p>

            <p className="mt-3 text-3xl font-bold text-violet-300">
              {totals.simulated}
            </p>
          </div>


          <div className="rounded-xl border border-emerald-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Executed
            </p>

            <p className="mt-3 text-3xl font-bold text-emerald-400">
              {totals.executed}
            </p>
          </div>


          <div className="rounded-xl border border-red-500/30 bg-[#0b1622] p-5">
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Safety Blocked
            </p>

            <p className="mt-3 text-3xl font-bold text-red-400">
              {totals.blocked}
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
              md:grid-cols-3
            "
          >

            <input
              value={
                search
              }
              onChange={
                (event) =>
                  setSearch(
                    event.target.value
                  )
              }
              placeholder="Search action, incident, target..."
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
                statusFilter
              }
              onChange={
                (event) =>
                  setStatusFilter(
                    event.target.value
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
                actionTypeFilter
              }
              onChange={
                (event) =>
                  setActionTypeFilter(
                    event.target.value
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
                All action types
              </option>

              {
                actionTypes.map(
                  (actionType) => (

                    <option
                      key={actionType}
                      value={actionType}
                    >
                      {actionType}
                    </option>

                  )
                )
              }

            </select>

          </div>


          <p
            className="
              mt-4
              text-sm
              text-slate-400
            "
          >
            Showing{" "}
            <strong className="text-slate-100">
              {filteredActions.length}
            </strong>{" "}
            of{" "}
            <strong className="text-slate-100">
              {actions.length}
            </strong>{" "}
            SOAR actions
          </p>

        </section>


        {/* ACTION TABLE */}

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

            <table className="min-w-full">

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
                    Action
                  </th>

                  <th className="px-4 py-4">
                    Target
                  </th>

                  <th className="px-4 py-4">
                    Status
                  </th>

                  <th className="px-4 py-4">
                    Approval
                  </th>

                  <th className="px-4 py-4">
                    Created
                  </th>

                  <th className="px-4 py-4">
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
                  filteredActions.map(
                    (action) => {

                      const busy =
                        operationLoading ===
                        action.id;


                      return (

                        <tr
                          key={
                            action.id
                          }
                          className="
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
                            #{action.id}
                          </td>


                          <td className="px-4 py-4">

                            <button
                              type="button"
                              onClick={
                                () =>
                                  router.push(
                                    `/incidents/${action.incident_id}`
                                  )
                              }
                              className="
                                text-cyan-300
                                hover:underline
                              "
                            >
                              Incident #
                              {
                                action.incident_id
                              }
                            </button>

                          </td>


                          <td
                            className="
                              px-4
                              py-4
                              font-medium
                            "
                          >
                            {
                              action.action_type
                            }
                          </td>


                          <td
                            className="
                              min-w-[200px]
                              px-4
                              py-4
                              font-mono
                              text-sm
                              text-slate-300
                            "
                          >
                            {
                              action.target
                            }
                          </td>


                          <td className="px-4 py-4">

                            <Badge
                              value={
                                action.status
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

                            {
                              action.requires_approval
                                ? (
                                  action.approved === true
                                    ? "Approved"
                                    : action.approved === false
                                      ? "Rejected"
                                      : "Required"
                                )
                                : "Not required"
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
                                action.created_at
                              )
                            }
                          </td>


                          <td
                            className="
                              min-w-[370px]
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
                                onClick={
                                  () =>
                                    void loadLogs(
                                      action
                                    )
                                }
                                className="
                                  rounded-lg
                                  border
                                  border-slate-600
                                  px-3
                                  py-1.5
                                  text-sm
                                  hover:bg-slate-800
                                "
                              >
                                Details
                              </button>


                              {
                                isAdmin &&
                                action.requires_approval &&
                                action.approved !== true &&
                                action.status !== "rejected" && (

                                  <button
                                    type="button"
                                    disabled={busy}
                                    onClick={
                                      () =>
                                        void runOperation(
                                          action,
                                          "approve"
                                        )
                                    }
                                    className="
                                      rounded-lg
                                      bg-emerald-600
                                      px-3
                                      py-1.5
                                      text-sm
                                      font-medium
                                      hover:bg-emerald-500
                                      disabled:opacity-50
                                    "
                                  >
                                    Approve
                                  </button>

                                )
                              }


                              {
                                isAdmin &&
                                action.status !== "rejected" &&
                                action.status !== "executed" &&
                                action.status !== "simulated" && (

                                  <button
                                    type="button"
                                    disabled={busy}
                                    onClick={
                                      () =>
                                        void runOperation(
                                          action,
                                          "reject"
                                        )
                                    }
                                    className="
                                      rounded-lg
                                      bg-red-600
                                      px-3
                                      py-1.5
                                      text-sm
                                      font-medium
                                      hover:bg-red-500
                                      disabled:opacity-50
                                    "
                                  >
                                    Reject
                                  </button>

                                )
                              }


                              {
                                isAdmin &&
                                action.status !== "executed" &&
                                action.status !== "simulated" &&
                                action.status !== "rejected" &&
                                action.status !== "blocked_by_safety" && (

                                  <button
                                    type="button"
                                    disabled={busy}
                                    onClick={
                                      () =>
                                        void runOperation(
                                          action,
                                          "execute"
                                        )
                                    }
                                    className="
                                      rounded-lg
                                      bg-violet-600
                                      px-3
                                      py-1.5
                                      text-sm
                                      font-medium
                                      hover:bg-violet-500
                                      disabled:opacity-50
                                    "
                                  >
                                    {
                                      busy
                                        ? "Processing..."
                                        : "Execute"
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
            filteredActions.length === 0 && (

              <div
                className="
                  p-10
                  text-center
                  text-slate-400
                "
              >
                No SOAR actions match
                the current filters.
              </div>

            )
          }

        </section>


        {/* SELECTED ACTION DETAILS */}

        {
          selectedAction && (

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
                  items-center
                  justify-between
                  gap-4
                "
              >

                <div>

                  <h2
                    className="
                      text-xl
                      font-bold
                    "
                  >
                    SOAR Action #
                    {
                      selectedAction.id
                    }
                  </h2>

                  <p
                    className="
                      mt-1
                      text-sm
                      text-slate-400
                    "
                  >
                    {
                      selectedAction.action_type
                    }
                    {" → "}
                    {
                      selectedAction.target
                    }
                  </p>

                </div>


                <Badge
                  value={
                    selectedAction.status
                  }
                />

              </div>


              <div
                className="
                  mt-6
                  grid
                  gap-4
                  lg:grid-cols-2
                "
              >

                <div
                  className="
                    rounded-lg
                    border
                    border-slate-700
                    bg-[#07111c]
                    p-4
                  "
                >

                  <h3
                    className="
                      font-semibold
                      text-slate-200
                    "
                  >
                    Execution Result
                  </h3>


                  <pre
                    className="
                      mt-4
                      max-h-[400px]
                      overflow-auto
                      whitespace-pre-wrap
                      break-words
                      text-xs
                      text-slate-300
                    "
                  >
                    {
                      formatJson(
                        selectedAction.result
                      )
                    }
                  </pre>

                </div>


                <div
                  className="
                    rounded-lg
                    border
                    border-slate-700
                    bg-[#07111c]
                    p-4
                  "
                >

                  <h3
                    className="
                      font-semibold
                      text-slate-200
                    "
                  >
                    Audit History
                  </h3>


                  {
                    logsLoading ? (

                      <p
                        className="
                          mt-4
                          text-sm
                          text-slate-400
                        "
                      >
                        Loading logs...
                      </p>

                    ) : selectedLogs.length === 0 ? (

                      <p
                        className="
                          mt-4
                          text-sm
                          text-slate-400
                        "
                      >
                        No audit events found.
                      </p>

                    ) : (

                      <div
                        className="
                          mt-4
                          space-y-3
                        "
                      >

                        {
                          selectedLogs.map(
                            (log) => (

                              <div
                                key={
                                  log.id
                                }
                                className="
                                  rounded-lg
                                  border
                                  border-slate-800
                                  p-3
                                "
                              >

                                <div
                                  className="
                                    flex
                                    flex-wrap
                                    items-center
                                    justify-between
                                    gap-2
                                  "
                                >

                                  <strong
                                    className="
                                      text-sm
                                      text-cyan-300
                                    "
                                  >
                                    {
                                      log.event_type
                                    }
                                  </strong>


                                  <span
                                    className="
                                      text-xs
                                      text-slate-500
                                    "
                                  >
                                    {
                                      formatDate(
                                        log.created_at
                                      )
                                    }
                                  </span>

                                </div>


                                <p
                                  className="
                                    mt-2
                                    text-xs
                                    text-slate-400
                                  "
                                >
                                  {
                                    log.previous_status
                                      ?? "none"
                                  }
                                  {" → "}
                                  {
                                    log.new_status
                                  }
                                </p>


                                {
                                  log.details !== null &&
                                  log.details !== undefined && (

                                    <pre
                                      className="
                                        mt-3
                                        max-h-[200px]
                                        overflow-auto
                                        whitespace-pre-wrap
                                        break-words
                                        text-xs
                                        text-slate-500
                                      "
                                    >
                                      {
                                        formatJson(
                                          log.details
                                        )
                                      }
                                    </pre>

                                  )
                                }

                              </div>

                            )
                          )
                        }

                      </div>

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