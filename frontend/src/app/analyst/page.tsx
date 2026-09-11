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


type RAGSource = {
  source?: string | null;
  score?: number | null;
};


type AnalystResponse = {
  question: string;
  answer: string;
  sources: RAGSource[];
};


type HistoryItem = {
  question: string;
  answer: string;
  sources: RAGSource[];
};


export default function AnalystPage() {
  const router =
    useRouter();


  const [
    loading,
    setLoading,
  ] =
    useState(true);


  const [
    asking,
    setAsking,
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
    question,
    setQuestion,
  ] =
    useState("");


  const [
    result,
    setResult,
  ] =
    useState<AnalystResponse | null>(
      null
    );


  const [
    history,
    setHistory,
  ] =
    useState<HistoryItem[]>(
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
          router.replace(
            "/login"
          );

          return;
        }

      } catch (authError) {
        console.error(
          "Unable to initialize analyst assistant:",
          authError
        );

        if (!active) {
          return;
        }

        setError(
          authError instanceof Error
            ? authError.message
            : "Unable to initialize analyst assistant"
        );

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
  // ASK
  // =====================================================

  async function askQuestion() {
    const normalizedQuestion =
      question.trim();

    if (
      normalizedQuestion.length < 3
    ) {
      setError(
        "Question must contain at least 3 characters."
      );

      return;
    }

    try {
      setAsking(
        true
      );

      setError(
        null
      );

      const data =
        await apiRequest<
          AnalystResponse
        >(
          "/analyst/ask",
          {
            method: "POST",

            body:
              JSON.stringify({
                question:
                  normalizedQuestion,
              }),
          }
        );

      setResult(
        data
      );

      setHistory(
        (current) => [
          {
            question:
              data.question,

            answer:
              data.answer,

            sources:
              data.sources,
          },

          ...current,
        ].slice(
          0,
          10
        )
      );

    } catch (requestError) {
      console.error(
        "Analyst assistant request failed:",
        requestError
      );

      setResult(
        null
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Analyst assistant request failed"
      );

    } finally {
      setAsking(
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
            mx-auto
            max-w-[1500px]
            rounded-xl
            border
            border-slate-700
            bg-[#0b1622]
            p-8
          "
        >
          Loading SOC Copilot...
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
                tracking-[0.25em]
                text-cyan-400
              "
            >
              RAG-Powered Analyst Assistant
            </p>

            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              SOC Copilot
            </h1>

            <p
              className="
                mt-2
                max-w-3xl
                text-sm
                text-slate-400
              "
            >
              Ask security questions and receive
              contextual answers grounded in the
              SOC knowledge base.
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


        {/* QUESTION */}

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
            Ask the SOC Copilot
          </h2>

          <p
            className="
              mt-2
              text-sm
              text-slate-400
            "
          >
            Example: What are the recommended
            investigation steps for a suspicious
            outbound connection?
          </p>


          <textarea
            value={
              question
            }
            onChange={
              (event) =>
                setQuestion(
                  event.target.value
                )
            }
            onKeyDown={
              (event) => {
                if (
                  event.key === "Enter" &&
                  (event.ctrlKey ||
                    event.metaKey)
                ) {
                  void askQuestion();
                }
              }
            }
            placeholder="Ask a cybersecurity question..."
            className="
              mt-5
              min-h-[150px]
              w-full
              resize-y
              rounded-xl
              border
              border-slate-700
              bg-[#07111c]
              p-4
              text-sm
              leading-6
              outline-none
              focus:border-cyan-500
            "
          />


          <div
            className="
              mt-4
              flex
              flex-wrap
              items-center
              justify-between
              gap-3
            "
          >
            <p
              className="
                text-xs
                text-slate-500
              "
            >
              Ctrl/Cmd + Enter to submit
            </p>


            <button
              type="button"
              disabled={
                asking
              }
              onClick={
                () =>
                  void askQuestion()
              }
              className="
                rounded-lg
                bg-cyan-500
                px-5
                py-3
                font-semibold
                text-slate-950
                hover:bg-cyan-400
                disabled:opacity-50
              "
            >
              {
                asking
                  ? "Thinking..."
                  : "Ask Copilot"
              }
            </button>
          </div>
        </section>


        {/* RESULT */}

        {
          result && (
            <section
              className="
                grid
                gap-5
                xl:grid-cols-[1.5fr_0.5fr]
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
                    tracking-[0.2em]
                    text-cyan-400
                  "
                >
                  Copilot Answer
                </p>

                <h2
                  className="
                    mt-3
                    text-xl
                    font-bold
                  "
                >
                  {
                    result.question
                  }
                </h2>

                <p
                  className="
                    mt-5
                    whitespace-pre-wrap
                    text-sm
                    leading-7
                    text-slate-300
                  "
                >
                  {
                    result.answer
                  }
                </p>
              </div>


              <div
                className="
                  rounded-xl
                  border
                  border-slate-700
                  bg-[#0b1622]
                  p-6
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
                  result.sources.length >
                  0 ? (
                    <div
                      className="
                        mt-4
                        space-y-3
                      "
                    >
                      {
                        result.sources.map(
                          (
                            source,
                            index
                          ) => (
                            <div
                              key={
                                `${source.source}-${index}`
                              }
                              className="
                                rounded-lg
                                border
                                border-slate-800
                                bg-[#07111c]
                                p-3
                              "
                            >
                              <p
                                className="
                                  break-all
                                  text-sm
                                  text-slate-300
                                "
                              >
                                {
                                  source.source ||
                                  "Unknown source"
                                }
                              </p>

                              <p
                                className="
                                  mt-2
                                  font-mono
                                  text-xs
                                  text-slate-500
                                "
                              >
                                Score:{" "}
                                {
                                  source.score ??
                                  "—"
                                }
                              </p>
                            </div>
                          )
                        )
                      }
                    </div>
                  ) : (
                    <p
                      className="
                        mt-4
                        text-sm
                        text-slate-500
                      "
                    >
                      No RAG sources returned.
                    </p>
                  )
                }
              </div>
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
              flex-wrap
              items-center
              justify-between
              gap-3
            "
          >
            <div>
              <h2
                className="
                  text-xl
                  font-bold
                "
              >
                Session History
              </h2>

              <p
                className="
                  mt-1
                  text-sm
                  text-slate-400
                "
              >
                Recent questions from this
                browser session.
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
                  Clear History
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
                  p-6
                  text-sm
                  text-slate-500
                "
              >
                No questions asked yet.
              </div>
            ) : (
              <div
                className="
                  mt-5
                  space-y-3
                "
              >
                {
                  history.map(
                    (
                      item,
                      index
                    ) => (
                      <button
                        key={
                          `${item.question}-${index}`
                        }
                        type="button"
                        onClick={
                          () => {
                            setQuestion(
                              item.question
                            );

                            setResult({
                              question:
                                item.question,

                              answer:
                                item.answer,

                              sources:
                                item.sources,
                            });
                          }
                        }
                        className="
                          w-full
                          rounded-lg
                          border
                          border-slate-800
                          bg-[#07111c]
                          p-4
                          text-left
                          transition
                          hover:border-cyan-500/50
                        "
                      >
                        <p
                          className="
                            font-semibold
                            text-slate-200
                          "
                        >
                          {
                            item.question
                          }
                        </p>

                        <p
                          className="
                            mt-2
                            line-clamp-2
                            text-sm
                            text-slate-500
                          "
                        >
                          {
                            item.answer
                          }
                        </p>
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