"use client";

import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  useRouter,
} from "next/navigation";

import {
  ApiError,
  apiRequest,
} from "@/lib/api";

import {
  initKeycloak,
  keycloak,
} from "@/lib/keycloak-auth";


type AdminUser = {
  id: string;
  username: string;
  email: string | null;
  first_name: string | null;
  last_name: string | null;
  enabled: boolean;
  roles: string[];
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


type CreateUserForm = {
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  password: string;
  role: "analyst" | "admin";
  enabled: boolean;
};


const initialCreateForm: CreateUserForm = {
  username: "",
  email: "",
  first_name: "",
  last_name: "",
  password: "",
  role: "analyst",
  enabled: true,
};


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


function roleBadgeClass(
  roles: string[]
) {
  if (
    roles.includes(
      "admin"
    )
  ) {
    return (
      "border-violet-500/40 " +
      "bg-violet-500/10 " +
      "text-violet-300"
    );
  }

  return (
    "border-cyan-500/40 " +
    "bg-cyan-500/10 " +
    "text-cyan-300"
  );
}


export default function AdminUsersPage() {
  const router =
    useRouter();


  const [
    users,
    setUsers,
  ] =
    useState<AdminUser[]>(
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


  const [
    roles,
    setRoles,
  ] =
    useState<string[]>(
      []
    );


  const [
    search,
    setSearch,
  ] =
    useState("");


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
    createForm,
    setCreateForm,
  ] =
    useState<CreateUserForm>(
      initialCreateForm
    );


  const [
    actionLoading,
    setActionLoading,
  ] =
    useState<string | null>(
      null
    );


  const isAdmin =
    roles.includes(
      "admin"
    );


  // =====================================================
  // INITIAL LOAD
  // =====================================================

  useEffect(() => {
    let active =
      true;

    async function initialize() {
      try {
        const authenticated =
          await initKeycloak();

        if (!active) {
          return;
        }

        if (!authenticated) {
          router.replace(
            "/login"
          );

          return;
        }

        const currentRoles =
          getCurrentRoles();

        setRoles(
          currentRoles
        );

        if (
          !currentRoles.includes(
            "admin"
          )
        ) {
          setError(
            "Administrator privileges are required to access user management."
          );

          return;
        }

        const data =
          await apiRequest<
            AdminUser[]
          >(
            "/admin/users"
          );

        if (!active) {
          return;
        }

        setUsers(
          data
        );

        setError(
          null
        );

      } catch (
        requestError
      ) {
        console.error(
          "Unable to initialize admin users page:",
          requestError
        );

        if (!active) {
          return;
        }

        if (
          requestError instanceof ApiError
        ) {
          if (
            requestError.status === 401
          ) {
            setError(
              "Your authentication session is no longer valid. Please sign in again."
            );

          } else if (
            requestError.status === 403
          ) {
            setError(
              "Administrator privileges are required."
            );

          } else if (
            requestError.status === 409
          ) {
            setError(
              "The requested user operation conflicts with an existing Keycloak account."
            );

          } else if (
            requestError.status === 502
          ) {
            setError(
              "The Keycloak administration service is unavailable or not authorized."
            );

          } else if (
            requestError.status === 503
          ) {
            setError(
              "The administration service is currently unavailable."
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
              : "Unable to load users"
          );
        }

      } finally {
        if (active) {
          setLoading(
            false
          );
        }
      }
    }

    void initialize();

    return () => {
      active =
        false;
    };

  }, [
    router,
  ]);


  // =====================================================
  // FILTER
  // =====================================================

  const filteredUsers =
    useMemo(
      () => {
        const query =
          search
            .trim()
            .toLowerCase();

        if (!query) {
          return users;
        }

        return users.filter(
          (user) => {
            const fullName =
              [
                user.first_name,
                user.last_name,
              ]
                .filter(Boolean)
                .join(" ")
                .toLowerCase();

            return (
              user.username
                .toLowerCase()
                .includes(query)
              ||
              (
                user.email
                  ?.toLowerCase()
                  .includes(query)
                ?? false
              )
              ||
              fullName.includes(
                query
              )
              ||
              user.roles.some(
                (role) =>
                  role
                    .toLowerCase()
                    .includes(query)
              )
            );
          }
        );
      },
      [
        search,
        users,
      ]
    );


  // =====================================================
  // REFRESH
  // =====================================================

  async function refreshUsers() {
    try {
      setRefreshing(
        true
      );

      setError(
        null
      );

      const data =
        await apiRequest<
          AdminUser[]
        >(
          "/admin/users"
        );

      setUsers(
        data
      );

    } catch (
      requestError
    ) {
      console.error(
        "Unable to refresh users:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to refresh users"
      );

    } finally {
      setRefreshing(
        false
      );
    }
  }


  // =====================================================
  // CREATE USER
  // =====================================================

  async function createUser() {
    const username =
      createForm.username.trim();

    const email =
      createForm.email.trim();

    const firstName =
      createForm.first_name.trim();

    const lastName =
      createForm.last_name.trim();

    if (!username) {
      setError(
        "Username is required."
      );

      return;
    }

    if (
      username.length < 3
    ) {
      setError(
        "Username must contain at least 3 characters."
      );

      return;
    }

    if (!email) {
      setError(
        "Email is required."
      );

      return;
    }

    if (
      createForm.password.length < 8
    ) {
      setError(
        "Password must contain at least 8 characters."
      );

      return;
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
          AdminUser
        >(
          "/admin/users",
          {
            method:
              "POST",

            body:
              JSON.stringify({
                username,

                email,

                first_name:
                  firstName || null,

                last_name:
                  lastName || null,

                password:
                  createForm.password,

                roles: [
                  createForm.role,
                ],

                enabled:
                  createForm.enabled,
              }),
          }
        );

      setUsers(
        (current) => [
          created,
          ...current,
        ]
      );

      setCreateForm(
        initialCreateForm
      );

      setCreateOpen(
        false
      );

    } catch (
      requestError
    ) {
      console.error(
        "Unable to create user:",
        requestError
      );

      if (
        requestError instanceof ApiError
        &&
        requestError.status === 409
      ) {
        setError(
          "A user with this username or email already exists."
        );

      } else if (
        requestError instanceof ApiError
        &&
        requestError.status === 400
      ) {
        setError(
          requestError.message
        );

      } else {
        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to create user"
        );
      }

    } finally {
      setCreateLoading(
        false
      );
    }
  }


  // =====================================================
  // ENABLE / DISABLE
  // =====================================================

  async function toggleEnabled(
    user: AdminUser
  ) {
    try {
      setActionLoading(
        user.id
      );

      setError(
        null
      );

      const updated =
        await apiRequest<
          AdminUser
        >(
          `/admin/users/${user.id}/enabled`,
          {
            method:
              "PUT",

            body:
              JSON.stringify({
                enabled:
                  !user.enabled,
              }),
          }
        );

      setUsers(
        (current) =>
          current.map(
            (item) =>
              item.id ===
              updated.id
                ? updated
                : item
          )
      );

    } catch (
      requestError
    ) {
      console.error(
        "Unable to update user state:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to update user state"
      );

    } finally {
      setActionLoading(
        null
      );
    }
  }


  // =====================================================
  // UPDATE ROLE
  // =====================================================

  async function updateRole(
    user: AdminUser,
    role:
      | "admin"
      | "analyst"
  ) {
    try {
      setActionLoading(
        user.id
      );

      setError(
        null
      );

      const updated =
        await apiRequest<
          AdminUser
        >(
          `/admin/users/${user.id}/roles`,
          {
            method:
              "PUT",

            body:
              JSON.stringify({
                roles: [
                  role,
                ],
              }),
          }
        );

      setUsers(
        (current) =>
          current.map(
            (item) =>
              item.id ===
              updated.id
                ? updated
                : item
          )
      );

    } catch (
      requestError
    ) {
      console.error(
        "Unable to update user role:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to update role"
      );

    } finally {
      setActionLoading(
        null
      );
    }
  }


  // =====================================================
  // RESET PASSWORD
  // =====================================================

  async function resetPassword(
    user: AdminUser
  ) {
    const password =
      window.prompt(
        `Enter a new password for ${user.username}:`
      );

    if (
      password === null
    ) {
      return;
    }

    if (
      password.length < 8
    ) {
      setError(
        "Password must contain at least 8 characters."
      );

      return;
    }

    const temporary =
      window.confirm(
        "Should this password be temporary?\n\nOK = temporary\nCancel = permanent"
      );

    try {
      setActionLoading(
        user.id
      );

      setError(
        null
      );

      await apiRequest<void>(
        `/admin/users/${user.id}/password`,
        {
          method:
            "PUT",

          body:
            JSON.stringify({
              password,
              temporary,
            }),
        }
      );

      window.alert(
        `Password updated for ${user.username}.`
      );

    } catch (
      requestError
    ) {
      console.error(
        "Unable to reset password:",
        requestError
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to reset password"
      );

    } finally {
      setActionLoading(
        null
      );
    }
  }


  // =====================================================
// DELETE USER
// =====================================================

async function deleteUser(
  user: AdminUser
) {
  try {
    setActionLoading(
      user.id
    );

    setError(
      null
    );

    await apiRequest<void>(
      `/admin/users/${user.id}`,
      {
        method: "DELETE",
      }
    );

    setUsers(
      (current) =>
        current.filter(
          (item) =>
            item.id !== user.id
        )
    );

    window.alert(
      `User "${user.username}" deleted successfully.`
    );

  } catch (
    requestError
  ) {
    console.error(
      "Unable to delete user:",
      requestError
    );

    if (
      requestError instanceof ApiError
    ) {
      setError(
        `Delete failed (${requestError.status}): ${requestError.message}`
      );

    } else {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to delete user"
      );
    }

  } finally {
    setActionLoading(
      null
    );
  }
}


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
            mx-auto
            max-w-[1600px]
            rounded-xl
            border
            border-slate-700
            bg-[#0b1622]
            p-8
          "
        >
          Loading user administration...
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
          max-w-[1600px]
          space-y-6
        "
      >

        {/* HEADER */}

        <section
          className="
            flex
            flex-col
            gap-4
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
                tracking-[0.28em]
                text-violet-400
              "
            >
              Identity & Access Management
            </p>

            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              User Administration
            </h1>

            <p
              className="
                mt-2
                max-w-3xl
                text-slate-400
              "
            >
              Manage SOC users, roles,
              account state and credentials
              through Keycloak.
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
                    : "text-red-400"
                }
              >
                {
                  isAdmin
                    ? "Administrator"
                    : "Unauthorized"
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


            {
              isAdmin && (
                <>
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
                      border-violet-500/50
                      px-4
                      py-2
                      text-sm
                      text-violet-300
                      hover:bg-violet-500/10
                    "
                  >
                    {
                      createOpen
                        ? "Close"
                        : "New User"
                    }
                  </button>


                  <button
                    type="button"
                    disabled={
                      refreshing
                    }
                    onClick={
                      () =>
                        void refreshUsers()
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
                </>
              )
            }
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


        {/* CREATE USER */}

        {
          isAdmin
          && createOpen
          && (
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
                Create SOC User
              </h2>


              <div
                className="
                  mt-5
                  grid
                  gap-4
                  md:grid-cols-2
                "
              >
                <input
                  value={
                    createForm.username
                  }
                  onChange={
                    (event) =>
                      setCreateForm(
                        (current) => ({
                          ...current,

                          username:
                            event.target.value,
                        })
                      )
                  }
                  placeholder="Username"
                  className="
                    rounded-lg
                    border
                    border-slate-700
                    bg-[#07111c]
                    px-4
                    py-3
                    outline-none
                    focus:border-cyan-500
                  "
                />


                <input
                  type="email"
                  value={
                    createForm.email
                  }
                  onChange={
                    (event) =>
                      setCreateForm(
                        (current) => ({
                          ...current,

                          email:
                            event.target.value,
                        })
                      )
                  }
                  placeholder="Email"
                  className="
                    rounded-lg
                    border
                    border-slate-700
                    bg-[#07111c]
                    px-4
                    py-3
                    outline-none
                    focus:border-cyan-500
                  "
                />


                <input
                  value={
                    createForm.first_name
                  }
                  onChange={
                    (event) =>
                      setCreateForm(
                        (current) => ({
                          ...current,

                          first_name:
                            event.target.value,
                        })
                      )
                  }
                  placeholder="First name"
                  className="
                    rounded-lg
                    border
                    border-slate-700
                    bg-[#07111c]
                    px-4
                    py-3
                    outline-none
                    focus:border-cyan-500
                  "
                />


                <input
                  value={
                    createForm.last_name
                  }
                  onChange={
                    (event) =>
                      setCreateForm(
                        (current) => ({
                          ...current,

                          last_name:
                            event.target.value,
                        })
                      )
                  }
                  placeholder="Last name"
                  className="
                    rounded-lg
                    border
                    border-slate-700
                    bg-[#07111c]
                    px-4
                    py-3
                    outline-none
                    focus:border-cyan-500
                  "
                />


                <input
                  type="password"
                  value={
                    createForm.password
                  }
                  onChange={
                    (event) =>
                      setCreateForm(
                        (current) => ({
                          ...current,

                          password:
                            event.target.value,
                        })
                      )
                  }
                  placeholder="Initial password"
                  className="
                    rounded-lg
                    border
                    border-slate-700
                    bg-[#07111c]
                    px-4
                    py-3
                    outline-none
                    focus:border-cyan-500
                  "
                />


                <select
                  value={
                    createForm.role
                  }
                  onChange={
                    (event) =>
                      setCreateForm(
                        (current) => ({
                          ...current,

                          role:
                            event.target.value as
                              | "analyst"
                              | "admin",
                        })
                      )
                  }
                  className="
                    rounded-lg
                    border
                    border-slate-700
                    bg-[#07111c]
                    px-4
                    py-3
                    outline-none
                    focus:border-cyan-500
                  "
                >
                  <option value="analyst">
                    Analyst
                  </option>

                  <option value="admin">
                    Administrator
                  </option>
                </select>
              </div>


              <label
                className="
                  mt-5
                  flex
                  items-center
                  gap-3
                  text-sm
                  text-slate-300
                "
              >
                <input
                  type="checkbox"
                  checked={
                    createForm.enabled
                  }
                  onChange={
                    (event) =>
                      setCreateForm(
                        (current) => ({
                          ...current,

                          enabled:
                            event.target.checked,
                        })
                      )
                  }
                />

                Account enabled
              </label>


              <button
                type="button"
                disabled={
                  createLoading
                }
                onClick={
                  () =>
                    void createUser()
                }
                className="
                  mt-5
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
                  createLoading
                    ? "Creating..."
                    : "Create User"
                }
              </button>
            </section>
          )
        }


        {/* FILTER */}

        {
          isAdmin && (
            <section
              className="
                rounded-xl
                border
                border-slate-700
                bg-[#0b1622]
                p-5
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
                placeholder="Search username, email, name or role..."
                className="
                  w-full
                  rounded-lg
                  border
                  border-slate-700
                  bg-[#07111c]
                  px-4
                  py-3
                  outline-none
                  focus:border-cyan-500
                "
              />

              <p
                className="
                  mt-3
                  text-sm
                  text-slate-500
                "
              >
                Showing{" "}
                <strong>
                  {filteredUsers.length}
                </strong>{" "}
                of{" "}
                <strong>
                  {users.length}
                </strong>{" "}
                users
              </p>
            </section>
          )
        }


        {/* USERS */}

        {
          isAdmin && (
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
                    w-full
                    min-w-[1100px]
                  "
                >
                  <thead
                    className="
                      border-b
                      border-slate-700
                      bg-slate-900/40
                    "
                  >
                    <tr
                      className="
                        text-left
                        text-xs
                        uppercase
                        tracking-wider
                        text-slate-500
                      "
                    >
                      <th
                        className="
                          px-5
                          py-4
                        "
                      >
                        User
                      </th>

                      <th
                        className="
                          px-5
                          py-4
                        "
                      >
                        Email
                      </th>

                      <th
                        className="
                          px-5
                          py-4
                        "
                      >
                        Role
                      </th>

                      <th
                        className="
                          px-5
                          py-4
                        "
                      >
                        Status
                      </th>

                      <th
                        className="
                          px-5
                          py-4
                        "
                      >
                        Actions
                      </th>
                    </tr>
                  </thead>


                  <tbody>
                    {
                      filteredUsers.map(
                        (user) => {
                          const busy =
                            actionLoading
                            === user.id;

                          const primaryRole:
                            | "admin"
                            | "analyst" =
                            user.roles.includes(
                              "admin"
                            )
                              ? "admin"
                              : "analyst";

                          return (
                            <tr
                              key={
                                user.id
                              }
                              className="
                                border-b
                                border-slate-800
                                last:border-b-0
                              "
                            >
                              <td
                                className="
                                  px-5
                                  py-5
                                "
                              >
                                <p
                                  className="
                                    font-semibold
                                  "
                                >
                                  {
                                    user.username
                                  }
                                </p>

                                <p
                                  className="
                                    mt-1
                                    text-sm
                                    text-slate-500
                                  "
                                >
                                  {
                                    [
                                      user.first_name,
                                      user.last_name,
                                    ]
                                      .filter(Boolean)
                                      .join(" ")
                                    ||
                                    "No display name"
                                  }
                                </p>
                              </td>


                              <td
                                className="
                                  px-5
                                  py-5
                                  text-sm
                                  text-slate-300
                                "
                              >
                                {
                                  user.email
                                  || "—"
                                }
                              </td>


                              <td
                                className="
                                  px-5
                                  py-5
                                "
                              >
                                <div
                                  className="
                                    flex
                                    flex-col
                                    gap-2
                                  "
                                >
                                  <span
                                    className={[
                                      "w-fit",
                                      "rounded-full",
                                      "border",
                                      "px-3",
                                      "py-1",
                                      "text-xs",

                                      roleBadgeClass(
                                        user.roles
                                      ),
                                    ].join(" ")}
                                  >
                                    {
                                      primaryRole
                                    }
                                  </span>


                                  <select
                                    value={
                                      primaryRole
                                    }
                                    disabled={
                                      busy
                                    }
                                    onChange={
                                      (event) =>
                                        void updateRole(
                                          user,

                                          event.target.value as
                                            | "analyst"
                                            | "admin"
                                        )
                                    }
                                    className="
                                      rounded-md
                                      border
                                      border-slate-700
                                      bg-[#07111c]
                                      px-3
                                      py-2
                                      text-sm
                                    "
                                  >
                                    <option
                                      value="analyst"
                                    >
                                      analyst
                                    </option>

                                    <option
                                      value="admin"
                                    >
                                      admin
                                    </option>
                                  </select>
                                </div>
                              </td>


                              <td
                                className="
                                  px-5
                                  py-5
                                "
                              >
                                <span
                                  className={
                                    user.enabled
                                      ? `
                                        rounded-full
                                        border
                                        border-emerald-500/40
                                        bg-emerald-500/10
                                        px-3
                                        py-1
                                        text-xs
                                        text-emerald-400
                                      `
                                      : `
                                        rounded-full
                                        border
                                        border-red-500/40
                                        bg-red-500/10
                                        px-3
                                        py-1
                                        text-xs
                                        text-red-400
                                      `
                                  }
                                >
                                  {
                                    user.enabled
                                      ? "Enabled"
                                      : "Disabled"
                                  }
                                </span>
                              </td>


                              <td
                                className="
                                  px-5
                                  py-5
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
                                      busy
                                    }
                                    onClick={
                                      () =>
                                        void toggleEnabled(
                                          user
                                        )
                                    }
                                    className="
                                      rounded-lg
                                      border
                                      border-slate-600
                                      px-3
                                      py-2
                                      text-xs
                                      hover:bg-slate-800
                                      disabled:opacity-50
                                    "
                                  >
                                    {
                                      user.enabled
                                        ? "Disable"
                                        : "Enable"
                                    }
                                  </button>


                                  <button
                                    type="button"
                                    disabled={
                                      busy
                                    }
                                    onClick={
                                      () =>
                                        void resetPassword(
                                          user
                                        )
                                    }
                                    className="
                                      rounded-lg
                                      border
                                      border-cyan-500/50
                                      px-3
                                      py-2
                                      text-xs
                                      text-cyan-300
                                      hover:bg-cyan-500/10
                                      disabled:opacity-50
                                    "
                                  >
                                    Reset Password
                                  </button>


                                  <button
                                    type="button"
                                    disabled={
                                      busy
                                    }
                                    onClick={
                                      () =>
                                        void deleteUser(
                                          user
                                        )
                                    }
                                    className="
                                      rounded-lg
                                      border
                                      border-red-500/50
                                      px-3
                                      py-2
                                      text-xs
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
                filteredUsers.length ===
                0 && (
                  <div
                    className="
                      p-10
                      text-center
                      text-slate-400
                    "
                  >
                    No users match the current search.
                  </div>
                )
              }
            </section>
          )
        }


        {/* FORBIDDEN */}

        {
          !isAdmin && (
            <section
              className="
                rounded-xl
                border
                border-red-500/30
                bg-red-500/10
                p-8
              "
            >
              <h2
                className="
                  text-xl
                  font-bold
                  text-red-300
                "
              >
                Access Restricted
              </h2>

              <p
                className="
                  mt-2
                  text-slate-400
                "
              >
                This page is available only
                to SOC administrators.
              </p>
            </section>
          )
        }

      </div>
    </main>
  );
}