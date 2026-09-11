"use client";

import {
  useEffect,
  useState,
} from "react";

import { useRouter } from "next/navigation";

import {
  apiRequest,
} from "@/lib/api";

import {
  initKeycloak,
} from "@/lib/keycloak-auth";


type MitreTechnique = {
  technique_id?: string | null;
  name?: string | null;
  description?: string | null;
  valid?: boolean;
  error?: string | null;
};


type SearchHistoryItem = {
  id: string;
  name?: string | null;
  valid: boolean;
};


function normalizeTechniqueId(
  value: string
) {
  return value
    .trim()
    .toUpperCase();
}


export default function MitrePage() {
  const router =
    useRouter();

  const [loading, setLoading] =
    useState(true);

  const [searching, setSearching] =
    useState(false);

  const [error, setError] =
    useState<string | null>(
      null
    );

  const [
    techniqueId,
    setTechniqueId,
  ] =
    useState("");

  const [
    result,
    setResult,
  ] =
    useState<MitreTechnique | null>(
      null
    );

  const [
    history,
    setHistory,
  ] =
    useState<SearchHistoryItem[]>(
      []
    );


  // =====================================================
  // AUTH
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
          router.push(
            "/login"
          );

          return;
        }

      } catch (authError) {
        console.error(
          "Unable to initialize MITRE page:",
          authError
        );

        if (!active) {
          return;
        }

        setError(
          authError instanceof Error
            ? authError.message
            : "Unable to initialize page"
        );

      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    void initialize();

    return () => {
      active =
        false;
    };

  }, [router]);


  // =====================================================
  // SEARCH
  // =====================================================

  async function searchTechnique(
    requestedId?: string
  ) {
    const value =
      normalizeTechniqueId(
        requestedId ??
        techniqueId
      );

    if (!value) {
      setError(
        "Enter a MITRE ATT&CK technique ID."
      );

      return;
    }

    if (
      !/^T\d{4}(?:\.\d{3})?$/.test(
        value
      )
    ) {
      setError(
        "Invalid MITRE ATT&CK ID format. Example: T1059 or T1016.001."
      );

      return;
    }

    try {
      setSearching(
        true
      );

      setError(
        null
      );

      setTechniqueId(
        value
      );

      const data =
        await apiRequest<
          MitreTechnique
        >(
          `/mitre/technique/${encodeURIComponent(
            value
          )}`
        );

      setResult(
        data
      );

      const historyItem: SearchHistoryItem = {
        id:
          data.technique_id ||
          value,

        name:
          data.name,

        valid:
          Boolean(
            data.valid
          ),
      };

      setHistory(
        (current) => {
          const filtered =
            current.filter(
              (item) =>
                item.id !==
                historyItem.id
            );

          return [
            historyItem,
            ...filtered,
          ].slice(
            0,
            8
          );
        }
      );

    } catch (requestError) {
      console.error(
        "Unable to validate MITRE technique:",
        requestError
      );

      setResult(
        null
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to validate MITRE technique"
      );

    } finally {
      setSearching(
        false
      );
    }
  }


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
          Loading MITRE ATT&CK...
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
          max-w-[1500px]
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
                text-violet-400
              "
            >
              Adversary Technique Validation
            </p>

            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              MITRE ATT&CK
            </h1>

            <p
              className="
                mt-2
                text-sm
                text-slate-400
              "
            >
              Validate MITRE ATT&CK technique IDs
              and review their official technique
              information.
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
                    "/ai-analysis"
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
              AI Analysis
            </button>


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
              Reports
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


        {/* SEARCH */}

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
            Validate Technique
          </h2>

          <p
            className="
              mt-2
              text-sm
              text-slate-400
            "
          >
            Examples:
            T1059,
            T1571,
            T1016.001
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
              value={
                techniqueId
              }
              onChange={
                (event) =>
                  setTechniqueId(
                    event.target.value
                  )
              }
              onKeyDown={
                (event) => {
                  if (
                    event.key ===
                    "Enter"
                  ) {
                    void searchTechnique();
                  }
                }
              }
              placeholder="MITRE technique ID"
              className="
                min-w-[280px]
                rounded-lg
                border
                border-slate-600
                bg-[#07111c]
                px-4
                py-3
                font-mono
                outline-none
                focus:border-violet-500
              "
            />


            <button
              type="button"
              disabled={
                searching
              }
              onClick={
                () =>
                  void searchTechnique()
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
                searching
                  ? "Validating..."
                  : "Validate Technique"
              }
            </button>
          </div>
        </section>


        {/* RESULT */}

        {
          result && (
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
                    Technique
                  </p>

                  <h2
                    className="
                      mt-2
                      font-mono
                      text-3xl
                      font-bold
                      text-violet-300
                    "
                  >
                    {
                      result.technique_id ||
                      techniqueId
                    }
                  </h2>
                </div>


                <span
                  className={[
                    "inline-flex",
                    "rounded-full",
                    "border",
                    "px-3",
                    "py-1.5",
                    "text-sm",
                    "font-semibold",

                    result.valid
                      ? (
                        "border-emerald-500/40 " +
                        "bg-emerald-500/10 " +
                        "text-emerald-400"
                      )
                      : (
                        "border-red-500/40 " +
                        "bg-red-500/10 " +
                        "text-red-400"
                      ),
                  ].join(
                    " "
                  )}
                >
                  {
                    result.valid
                      ? "Valid"
                      : "Invalid"
                  }
                </span>
              </div>


              <div
                className="
                  mt-6
                  grid
                  gap-5
                  lg:grid-cols-2
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
                  <p
                    className="
                      text-xs
                      uppercase
                      tracking-wider
                      text-slate-500
                    "
                  >
                    Technique Name
                  </p>

                  <p
                    className="
                      mt-3
                      text-xl
                      font-semibold
                    "
                  >
                    {
                      result.name ||
                      "Unknown technique"
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
                  <p
                    className="
                      text-xs
                      uppercase
                      tracking-wider
                      text-slate-500
                    "
                  >
                    Validation
                  </p>

                  <p
                    className="
                      mt-3
                      text-xl
                      font-semibold
                    "
                  >
                    {
                      result.valid
                        ? "Recognized by MITRE ATT&CK"
                        : "Technique not validated"
                    }
                  </p>
                </div>
              </div>


              <div
                className="
                  mt-5
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
                  Description
                </h3>

                <p
                  className="
                    mt-4
                    whitespace-pre-wrap
                    leading-7
                    text-slate-300
                  "
                >
                  {
                    result.description ||
                    "No MITRE ATT&CK description available."
                  }
                </p>
              </div>


              {
                result.error && (
                  <div
                    className="
                      mt-5
                      rounded-xl
                      border
                      border-red-500/30
                      bg-red-500/10
                      p-4
                      text-sm
                      text-red-300
                    "
                  >
                    {
                      result.error
                    }
                  </div>
                )
              }
            </section>
          )
        }


        {/* HISTORY */}

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
                Recent Lookups
              </h2>

              <p
                className="
                  mt-2
                  text-sm
                  text-slate-400
                "
              >
                Recent MITRE techniques checked
                during this browser session.
              </p>
            </div>


            {
              history.length > 0 && (
                <button
                  type="button"
                  onClick={
                    () =>
                      setHistory(
                        []
                      )
                  }
                  className="
                    rounded-lg
                    border
                    border-slate-600
                    px-3
                    py-2
                    text-sm
                    hover:bg-slate-800
                  "
                >
                  Clear
                </button>
              )
            }
          </div>


          {
            history.length === 0 ? (
              <div
                className="
                  mt-5
                  rounded-lg
                  border
                  border-slate-800
                  p-5
                  text-sm
                  text-slate-500
                "
              >
                No MITRE technique has been
                searched yet.
              </div>
            ) : (
              <div
                className="
                  mt-5
                  grid
                  gap-3
                  md:grid-cols-2
                "
              >
                {
                  history.map(
                    (item) => (
                      <button
                        type="button"
                        key={
                          item.id
                        }
                        onClick={
                          () =>
                            void searchTechnique(
                              item.id
                            )
                        }
                        className="
                          flex
                          items-center
                          justify-between
                          gap-4
                          rounded-lg
                          border
                          border-slate-700
                          bg-[#07111c]
                          p-4
                          text-left
                          hover:border-violet-500/50
                          hover:bg-slate-900
                        "
                      >
                        <div>
                          <p
                            className="
                              font-mono
                              font-semibold
                              text-violet-300
                            "
                          >
                            {
                              item.id
                            }
                          </p>

                          <p
                            className="
                              mt-1
                              text-sm
                              text-slate-400
                            "
                          >
                            {
                              item.name ||
                              "Unknown technique"
                            }
                          </p>
                        </div>


                        <span
                          className={
                            item.valid
                              ? "text-emerald-400"
                              : "text-red-400"
                          }
                        >
                          {
                            item.valid
                              ? "Valid"
                              : "Invalid"
                          }
                        </span>
                      </button>
                    )
                  )
                }
              </div>
            )
          }
        </section>

      </div>
    </main>
  );
}