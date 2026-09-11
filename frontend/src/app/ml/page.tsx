"use client";

import {
  useEffect,
  useMemo,
  useState,
} from "react";

import { useRouter } from "next/navigation";

import {
  apiRequest,
} from "@/lib/api";

import {
  initKeycloak,
} from "@/lib/keycloak-auth";


type TrafficPredictionResponse = {
  status: string;
  prediction: string;
  benign_probability: number;
  ddos_probability: number;
  portscan_probability: number;
  ftp_patator_probability: number;
  ssh_patator_probability: number;
};


type SuricataAnomalyResponse = {
  status: string;
  prediction: string;
  is_anomaly: boolean;
  anomaly_score: number;
  features: Record<string, number>;
};


type SuricataForm = {
  destPort: string;
  age: string;

  pktsToServer: string;
  pktsToClient: string;

  bytesToServer: string;
  bytesToClient: string;

  syn: boolean;
  fin: boolean;
  psh: boolean;
  ack: boolean;

  alerted: boolean;
};


const CICIDS_FEATURES = [
  "Destination Port",
  "Flow Duration",
  "Total Fwd Packets",
  "Total Backward Packets",
  "Total Length of Fwd Packets",
  "Total Length of Bwd Packets",
  "Fwd Packet Length Max",
  "Fwd Packet Length Min",
  "Fwd Packet Length Mean",
  "Fwd Packet Length Std",
  "Bwd Packet Length Max",
  "Bwd Packet Length Min",
  "Bwd Packet Length Mean",
  "Bwd Packet Length Std",
  "Flow Bytes/s",
  "Flow Packets/s",
  "Flow IAT Mean",
  "Flow IAT Std",
  "Flow IAT Max",
  "Flow IAT Min",
  "Fwd IAT Total",
  "Fwd IAT Mean",
  "Fwd IAT Std",
  "Fwd IAT Max",
  "Fwd IAT Min",
  "Bwd IAT Total",
  "Bwd IAT Mean",
  "Bwd IAT Std",
  "Bwd IAT Max",
  "Bwd IAT Min",
  "Fwd PSH Flags",
  "Bwd PSH Flags",
  "Fwd URG Flags",
  "Bwd URG Flags",
  "Fwd Header Length",
  "Bwd Header Length",
  "Fwd Packets/s",
  "Bwd Packets/s",
  "Min Packet Length",
  "Max Packet Length",
  "Packet Length Mean",
  "Packet Length Std",
  "Packet Length Variance",
  "FIN Flag Count",
  "SYN Flag Count",
  "RST Flag Count",
  "PSH Flag Count",
  "ACK Flag Count",
  "URG Flag Count",
  "CWE Flag Count",
  "ECE Flag Count",
  "Down/Up Ratio",
  "Average Packet Size",
  "Avg Fwd Segment Size",
  "Avg Bwd Segment Size",
  "Fwd Header Length.1",
  "Fwd Avg Bytes/Bulk",
  "Fwd Avg Packets/Bulk",
  "Fwd Avg Bulk Rate",
  "Bwd Avg Bytes/Bulk",
  "Bwd Avg Packets/Bulk",
  "Bwd Avg Bulk Rate",
  "Subflow Fwd Packets",
  "Subflow Fwd Bytes",
  "Subflow Bwd Packets",
  "Subflow Bwd Bytes",
  "Init_Win_bytes_forward",
  "Init_Win_bytes_backward",
  "act_data_pkt_fwd",
  "min_seg_size_forward",
  "Active Mean",
  "Active Std",
  "Active Max",
  "Active Min",
  "Idle Mean",
  "Idle Std",
  "Idle Max",
  "Idle Min",
] as const;


const initialSuricataForm: SuricataForm = {
  destPort: "443",
  age: "5",

  pktsToServer: "10",
  pktsToClient: "8",

  bytesToServer: "1200",
  bytesToClient: "2400",

  syn: true,
  fin: false,
  psh: true,
  ack: true,

  alerted: false,
};


function createEmptyTrafficFeatures() {
  return Object.fromEntries(
    CICIDS_FEATURES.map(
      (feature) => [
        feature,
        0,
      ]
    )
  ) as Record<string, number>;
}


function percent(
  value?: number
) {
  if (
    value === undefined ||
    Number.isNaN(value)
  ) {
    return "0.00%";
  }

  return `${(
    value * 100
  ).toFixed(2)}%`;
}


function predictionClass(
  value?: string | null
) {
  switch (
    value
      ?.trim()
      .toLowerCase()
  ) {
    case "benign":
    case "normal":
      return (
        "border-emerald-500/40 " +
        "bg-emerald-500/10 " +
        "text-emerald-400"
      );

    case "ddos":
    case "portscan":
    case "ftp-patator":
    case "ssh-patator":
    case "anomaly":
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


export default function MLPage() {
  const router =
    useRouter();


  const [
    loading,
    setLoading,
  ] =
    useState(true);


  const [
    error,
    setError,
  ] =
    useState<string | null>(
      null
    );


  const [
    trafficLoading,
    setTrafficLoading,
  ] =
    useState(false);


  const [
    trafficJson,
    setTrafficJson,
  ] =
    useState(
      JSON.stringify(
        createEmptyTrafficFeatures(),
        null,
        2
      )
    );


  const [
    trafficResult,
    setTrafficResult,
  ] =
    useState<
      TrafficPredictionResponse | null
    >(
      null
    );


  const [
    suricataLoading,
    setSuricataLoading,
  ] =
    useState(false);


  const [
    suricataForm,
    setSuricataForm,
  ] =
    useState<SuricataForm>(
      initialSuricataForm
    );


  const [
    suricataResult,
    setSuricataResult,
  ] =
    useState<
      SuricataAnomalyResponse | null
    >(
      null
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
          "Unable to initialize ML page:",
          authError
        );

        if (!active) {
          return;
        }

        setError(
          authError instanceof Error
            ? authError.message
            : "Unable to initialize ML page"
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

  }, [router]);


  // =====================================================
  // RANDOM FOREST PREDICTION
  // =====================================================

  async function predictTraffic() {
    try {
      setTrafficLoading(
        true
      );

      setError(
        null
      );

      let parsed: unknown;

      try {
        parsed =
          JSON.parse(
            trafficJson
          );
      } catch {
        throw new Error(
          "Traffic features must contain valid JSON."
        );
      }

      if (
        typeof parsed !==
          "object" ||
        parsed === null ||
        Array.isArray(
          parsed
        )
      ) {
        throw new Error(
          "Traffic features must be a JSON object."
        );
      }

      const input =
        parsed as Record<
          string,
          unknown
        >;


      const missing =
        CICIDS_FEATURES.filter(
          (feature) =>
            !Object.prototype.hasOwnProperty.call(
              input,
              feature
            )
        );


      if (
        missing.length > 0
      ) {
        throw new Error(
          `Missing CICIDS2017 features: ${missing
            .slice(
              0,
              5
            )
            .join(
              ", "
            )}${
            missing.length > 5
              ? "..."
              : ""
          }`
        );
      }


      const orderedFeatures:
        Record<
          string,
          number
        > =
        {};


      for (
        const feature
        of CICIDS_FEATURES
      ) {
        const value =
          Number(
            input[
              feature
            ]
          );

        if (
          !Number.isFinite(
            value
          )
        ) {
          throw new Error(
            `Feature "${feature}" must be numeric.`
          );
        }

        orderedFeatures[
          feature
        ] =
          value;
      }


      const data =
        await apiRequest<
          TrafficPredictionResponse
        >(
          "/ml/predict",
          {
            method: "POST",

            body:
              JSON.stringify({
                features:
                  orderedFeatures,
              }),
          }
        );


      setTrafficResult(
        data
      );

    } catch (requestError) {
      console.error(
        "Unable to predict network traffic:",
        requestError
      );

      setTrafficResult(
        null
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Traffic prediction failed"
      );

    } finally {
      setTrafficLoading(
        false
      );
    }
  }


  function resetTrafficFeatures() {
    setTrafficJson(
      JSON.stringify(
        createEmptyTrafficFeatures(),
        null,
        2
      )
    );

    setTrafficResult(
      null
    );

    setError(
      null
    );
  }


  // =====================================================
  // SURICATA ANOMALY
  // =====================================================

  async function predictSuricataAnomaly() {
    try {
      setSuricataLoading(
        true
      );

      setError(
        null
      );


      const destPort =
        Number(
          suricataForm.destPort
        );

      const age =
        Number(
          suricataForm.age
        );

      const pktsToServer =
        Number(
          suricataForm.pktsToServer
        );

      const pktsToClient =
        Number(
          suricataForm.pktsToClient
        );

      const bytesToServer =
        Number(
          suricataForm.bytesToServer
        );

      const bytesToClient =
        Number(
          suricataForm.bytesToClient
        );


      const numericValues = [
        destPort,
        age,
        pktsToServer,
        pktsToClient,
        bytesToServer,
        bytesToClient,
      ];


      if (
        numericValues.some(
          (value) =>
            !Number.isFinite(
              value
            )
        )
      ) {
        throw new Error(
          "All Suricata numeric fields must contain valid numbers."
        );
      }


      if (
        destPort < 0 ||
        destPort > 65535
      ) {
        throw new Error(
          "Destination port must be between 0 and 65535."
        );
      }


      if (
        age < 0 ||
        pktsToServer < 0 ||
        pktsToClient < 0 ||
        bytesToServer < 0 ||
        bytesToClient < 0
      ) {
        throw new Error(
          "Suricata flow counters cannot be negative."
        );
      }


      const event = {
        event_type:
          "flow",

        dest_port:
          destPort,

        flow: {
          age,

          pkts_toserver:
            pktsToServer,

          pkts_toclient:
            pktsToClient,

          bytes_toserver:
            bytesToServer,

          bytes_toclient:
            bytesToClient,

          alerted:
            suricataForm.alerted,
        },

        tcp: {
          syn:
            suricataForm.syn,

          fin:
            suricataForm.fin,

          psh:
            suricataForm.psh,

          ack:
            suricataForm.ack,
        },
      };


      const data =
        await apiRequest<
          SuricataAnomalyResponse
        >(
          "/ml/suricata-anomaly",
          {
            method: "POST",

            body:
              JSON.stringify(
                event
              ),
          }
        );


      setSuricataResult(
        data
      );

    } catch (requestError) {
      console.error(
        "Unable to analyze Suricata flow:",
        requestError
      );

      setSuricataResult(
        null
      );

      setError(
        requestError instanceof Error
          ? requestError.message
          : "Suricata anomaly prediction failed"
      );

    } finally {
      setSuricataLoading(
        false
      );
    }
  }


  const trafficProbabilities =
    useMemo(() => {
      if (
        !trafficResult
      ) {
        return [];
      }

      return [
        {
          label:
            "BENIGN",

          value:
            trafficResult
              .benign_probability,
        },

        {
          label:
            "DDoS",

          value:
            trafficResult
              .ddos_probability,
        },

        {
          label:
            "PortScan",

          value:
            trafficResult
              .portscan_probability,
        },

        {
          label:
            "FTP-Patator",

          value:
            trafficResult
              .ftp_patator_probability,
        },

        {
          label:
            "SSH-Patator",

          value:
            trafficResult
              .ssh_patator_probability,
        },
      ];

    }, [
      trafficResult,
    ]);


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
          Loading Machine Learning...
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
          max-w-[1650px]
          space-y-8
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
                text-yellow-400
              "
            >
              Machine Learning Security Analytics
            </p>

            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              Machine Learning
            </h1>

            <p
              className="
                mt-2
                max-w-3xl
                text-sm
                text-slate-400
              "
            >
              Classify CICIDS2017 network traffic
              with the Random Forest model and
              detect anomalous Suricata flows with
              Isolation Forest.
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


        {/* RANDOM FOREST */}

        <section
          className="
            rounded-xl
            border
            border-cyan-500/30
            bg-[#0b1622]
            p-6
          "
        >
          <div
            className="
              flex
              flex-col
              gap-4
              xl:flex-row
              xl:items-start
              xl:justify-between
            "
          >
            <div>
              <p
                className="
                  text-xs
                  uppercase
                  tracking-[0.2em]
                  text-cyan-400
                "
              >
                Supervised Classification
              </p>

              <h2
                className="
                  mt-2
                  text-2xl
                  font-bold
                "
              >
                CICIDS2017 Random Forest
              </h2>

              <p
                className="
                  mt-2
                  max-w-3xl
                  text-sm
                  text-slate-400
                "
              >
                The deployed classifier expects
                exactly 78 CICIDS2017 features and
                predicts BENIGN, DDoS, PortScan,
                FTP-Patator or SSH-Patator.
              </p>
            </div>


            <div
              className="
                rounded-lg
                border
                border-cyan-500/30
                bg-cyan-500/10
                px-4
                py-3
                text-sm
                text-cyan-300
              "
            >
              78 input features
            </div>
          </div>


          <div
            className="
              mt-6
              grid
              gap-6
              xl:grid-cols-[1.25fr_0.75fr]
            "
          >
            <div>
              <div
                className="
                  mb-3
                  flex
                  flex-wrap
                  items-center
                  justify-between
                  gap-3
                "
              >
                <h3
                  className="
                    font-semibold
                  "
                >
                  Feature Vector
                </h3>


                <button
                  type="button"
                  onClick={
                    resetTrafficFeatures
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
                  Reset 78 Features
                </button>
              </div>


              <textarea
                spellCheck={
                  false
                }
                value={
                  trafficJson
                }
                onChange={
                  (event) =>
                    setTrafficJson(
                      event.target.value
                    )
                }
                className="
                  min-h-[580px]
                  w-full
                  resize-y
                  rounded-xl
                  border
                  border-slate-700
                  bg-[#07111c]
                  p-4
                  font-mono
                  text-sm
                  leading-6
                  text-slate-300
                  outline-none
                  focus:border-cyan-500
                "
              />


              <button
                type="button"
                disabled={
                  trafficLoading
                }
                onClick={
                  () =>
                    void predictTraffic()
                }
                className="
                  mt-4
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
                  trafficLoading
                    ? "Classifying..."
                    : "Run Traffic Classification"
                }
              </button>
            </div>


            <div
              className="
                space-y-4
              "
            >
              {
                trafficResult ? (
                  <>
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
                        Prediction
                      </p>

                      <span
                        className={[
                          "mt-4",
                          "inline-flex",
                          "rounded-full",
                          "border",
                          "px-4",
                          "py-2",
                          "text-lg",
                          "font-bold",
                          predictionClass(
                            trafficResult.prediction
                          ),
                        ].join(
                          " "
                        )}
                      >
                        {
                          trafficResult.prediction
                        }
                      </span>
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
                        "
                      >
                        Class Probabilities
                      </h3>


                      <div
                        className="
                          mt-5
                          space-y-4
                        "
                      >
                        {
                          trafficProbabilities.map(
                            (
                              item
                            ) => (
                              <div
                                key={
                                  item.label
                                }
                              >
                                <div
                                  className="
                                    flex
                                    items-center
                                    justify-between
                                    gap-4
                                    text-sm
                                  "
                                >
                                  <span>
                                    {
                                      item.label
                                    }
                                  </span>

                                  <span
                                    className="
                                      font-mono
                                      text-slate-300
                                    "
                                  >
                                    {
                                      percent(
                                        item.value
                                      )
                                    }
                                  </span>
                                </div>


                                <div
                                  className="
                                    mt-2
                                    h-2
                                    overflow-hidden
                                    rounded-full
                                    bg-slate-800
                                  "
                                >
                                  <div
                                    className="
                                      h-full
                                      bg-cyan-500
                                    "
                                    style={{
                                      width:
                                        `${Math.max(
                                          0,
                                          Math.min(
                                            100,
                                            item.value *
                                              100
                                          )
                                        )}%`,
                                    }}
                                  />
                                </div>
                              </div>
                            )
                          )
                        }
                      </div>
                    </div>
                  </>
                ) : (
                  <div
                    className="
                      rounded-xl
                      border
                      border-slate-700
                      bg-[#07111c]
                      p-8
                      text-sm
                      text-slate-500
                    "
                  >
                    Run the Random Forest
                    classifier to display its
                    predicted attack class and
                    confidence probabilities.
                  </div>
                )
              }
            </div>
          </div>
        </section>


        {/* SURICATA */}

        <section
          className="
            rounded-xl
            border
            border-violet-500/30
            bg-[#0b1622]
            p-6
          "
        >
          <div>
            <p
              className="
                text-xs
                uppercase
                tracking-[0.2em]
                text-violet-400
              "
            >
              Unsupervised Anomaly Detection
            </p>

            <h2
              className="
                mt-2
                text-2xl
                font-bold
              "
            >
              Suricata Isolation Forest
            </h2>

            <p
              className="
                mt-2
                max-w-3xl
                text-sm
                text-slate-400
              "
            >
              Build a Suricata flow event and
              detect whether its network behavior
              is normal or anomalous.
            </p>
          </div>


          <div
            className="
              mt-6
              grid
              gap-6
              xl:grid-cols-[1fr_0.9fr]
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
                "
              >
                Flow Event
              </h3>


              <div
                className="
                  mt-5
                  grid
                  gap-4
                  md:grid-cols-2
                "
              >
                <label
                  className="
                    space-y-2
                  "
                >
                  <span
                    className="
                      text-sm
                      text-slate-400
                    "
                  >
                    Destination Port
                  </span>

                  <input
                    type="number"
                    value={
                      suricataForm.destPort
                    }
                    onChange={
                      (event) =>
                        setSuricataForm(
                          (
                            current
                          ) => ({
                            ...current,

                            destPort:
                              event
                                .target
                                .value,
                          })
                        )
                    }
                    className="
                      w-full
                      rounded-lg
                      border
                      border-slate-600
                      bg-[#0b1622]
                      px-3
                      py-2
                      outline-none
                      focus:border-violet-500
                    "
                  />
                </label>


                <label
                  className="
                    space-y-2
                  "
                >
                  <span
                    className="
                      text-sm
                      text-slate-400
                    "
                  >
                    Flow Age (seconds)
                  </span>

                  <input
                    type="number"
                    value={
                      suricataForm.age
                    }
                    onChange={
                      (event) =>
                        setSuricataForm(
                          (
                            current
                          ) => ({
                            ...current,

                            age:
                              event
                                .target
                                .value,
                          })
                        )
                    }
                    className="
                      w-full
                      rounded-lg
                      border
                      border-slate-600
                      bg-[#0b1622]
                      px-3
                      py-2
                      outline-none
                      focus:border-violet-500
                    "
                  />
                </label>


                <label
                  className="
                    space-y-2
                  "
                >
                  <span
                    className="
                      text-sm
                      text-slate-400
                    "
                  >
                    Packets to Server
                  </span>

                  <input
                    type="number"
                    value={
                      suricataForm.pktsToServer
                    }
                    onChange={
                      (event) =>
                        setSuricataForm(
                          (
                            current
                          ) => ({
                            ...current,

                            pktsToServer:
                              event
                                .target
                                .value,
                          })
                        )
                    }
                    className="
                      w-full
                      rounded-lg
                      border
                      border-slate-600
                      bg-[#0b1622]
                      px-3
                      py-2
                      outline-none
                      focus:border-violet-500
                    "
                  />
                </label>


                <label
                  className="
                    space-y-2
                  "
                >
                  <span
                    className="
                      text-sm
                      text-slate-400
                    "
                  >
                    Packets to Client
                  </span>

                  <input
                    type="number"
                    value={
                      suricataForm.pktsToClient
                    }
                    onChange={
                      (event) =>
                        setSuricataForm(
                          (
                            current
                          ) => ({
                            ...current,

                            pktsToClient:
                              event
                                .target
                                .value,
                          })
                        )
                    }
                    className="
                      w-full
                      rounded-lg
                      border
                      border-slate-600
                      bg-[#0b1622]
                      px-3
                      py-2
                      outline-none
                      focus:border-violet-500
                    "
                  />
                </label>


                <label
                  className="
                    space-y-2
                  "
                >
                  <span
                    className="
                      text-sm
                      text-slate-400
                    "
                  >
                    Bytes to Server
                  </span>

                  <input
                    type="number"
                    value={
                      suricataForm.bytesToServer
                    }
                    onChange={
                      (event) =>
                        setSuricataForm(
                          (
                            current
                          ) => ({
                            ...current,

                            bytesToServer:
                              event
                                .target
                                .value,
                          })
                        )
                    }
                    className="
                      w-full
                      rounded-lg
                      border
                      border-slate-600
                      bg-[#0b1622]
                      px-3
                      py-2
                      outline-none
                      focus:border-violet-500
                    "
                  />
                </label>


                <label
                  className="
                    space-y-2
                  "
                >
                  <span
                    className="
                      text-sm
                      text-slate-400
                    "
                  >
                    Bytes to Client
                  </span>

                  <input
                    type="number"
                    value={
                      suricataForm.bytesToClient
                    }
                    onChange={
                      (event) =>
                        setSuricataForm(
                          (
                            current
                          ) => ({
                            ...current,

                            bytesToClient:
                              event
                                .target
                                .value,
                          })
                        )
                    }
                    className="
                      w-full
                      rounded-lg
                      border
                      border-slate-600
                      bg-[#0b1622]
                      px-3
                      py-2
                      outline-none
                      focus:border-violet-500
                    "
                  />
                </label>
              </div>


              <div
                className="
                  mt-6
                  rounded-xl
                  border
                  border-slate-700
                  p-4
                "
              >
                <p
                  className="
                    text-sm
                    font-semibold
                  "
                >
                  TCP Flags
                </p>


                <div
                  className="
                    mt-4
                    flex
                    flex-wrap
                    gap-5
                  "
                >
                  {
                    (
                      [
                        [
                          "syn",
                          "SYN",
                        ],

                        [
                          "fin",
                          "FIN",
                        ],

                        [
                          "psh",
                          "PSH",
                        ],

                        [
                          "ack",
                          "ACK",
                        ],
                      ] as const
                    ).map(
                      ([
                        field,
                        label,
                      ]) => (
                        <label
                          key={
                            field
                          }
                          className="
                            flex
                            items-center
                            gap-2
                            text-sm
                          "
                        >
                          <input
                            type="checkbox"
                            checked={
                              suricataForm[
                                field
                              ]
                            }
                            onChange={
                              (
                                event
                              ) =>
                                setSuricataForm(
                                  (
                                    current
                                  ) => ({
                                    ...current,

                                    [field]:
                                      event
                                        .target
                                        .checked,
                                  })
                                )
                            }
                          />

                          {
                            label
                          }
                        </label>
                      )
                    )
                  }


                  <label
                    className="
                      flex
                      items-center
                      gap-2
                      text-sm
                    "
                  >
                    <input
                      type="checkbox"
                      checked={
                        suricataForm.alerted
                      }
                      onChange={
                        (event) =>
                          setSuricataForm(
                            (
                              current
                            ) => ({
                              ...current,

                              alerted:
                                event
                                  .target
                                  .checked,
                            })
                          )
                      }
                    />

                    Flow Alerted
                  </label>
                </div>
              </div>


              <button
                type="button"
                disabled={
                  suricataLoading
                }
                onClick={
                  () =>
                    void predictSuricataAnomaly()
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
                  suricataLoading
                    ? "Analyzing..."
                    : "Detect Flow Anomaly"
                }
              </button>
            </div>


            <div
              className="
                space-y-4
              "
            >
              {
                suricataResult ? (
                  <>
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
                        Prediction
                      </p>


                      <span
                        className={[
                          "mt-4",
                          "inline-flex",
                          "rounded-full",
                          "border",
                          "px-4",
                          "py-2",
                          "text-lg",
                          "font-bold",
                          predictionClass(
                            suricataResult.prediction
                          ),
                        ].join(
                          " "
                        )}
                      >
                        {
                          suricataResult.prediction
                        }
                      </span>


                      <div
                        className="
                          mt-5
                          grid
                          gap-4
                          sm:grid-cols-2
                        "
                      >
                        <div>
                          <p
                            className="
                              text-xs
                              uppercase
                              text-slate-500
                            "
                          >
                            Is Anomaly
                          </p>

                          <p
                            className="
                              mt-2
                              font-semibold
                            "
                          >
                            {
                              suricataResult.is_anomaly
                                ? "Yes"
                                : "No"
                            }
                          </p>
                        </div>


                        <div>
                          <p
                            className="
                              text-xs
                              uppercase
                              text-slate-500
                            "
                          >
                            Decision Score
                          </p>

                          <p
                            className="
                              mt-2
                              font-mono
                              font-semibold
                            "
                          >
                            {
                              suricataResult
                                .anomaly_score
                                .toFixed(
                                  6
                                )
                            }
                          </p>
                        </div>
                      </div>
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
                        Extracted ML Features
                      </h3>


                      <div
                        className="
                          mt-4
                          grid
                          gap-3
                          sm:grid-cols-2
                        "
                      >
                        {
                          Object.entries(
                            suricataResult.features
                          ).map(
                            ([
                              key,
                              value,
                            ]) => (
                              <div
                                key={
                                  key
                                }
                                className="
                                  rounded-lg
                                  border
                                  border-slate-800
                                  p-3
                                "
                              >
                                <p
                                  className="
                                    text-xs
                                    text-slate-500
                                  "
                                >
                                  {
                                    key
                                  }
                                </p>

                                <p
                                  className="
                                    mt-1
                                    break-all
                                    font-mono
                                    text-sm
                                    text-slate-200
                                  "
                                >
                                  {
                                    String(
                                      value
                                    )
                                  }
                                </p>
                              </div>
                            )
                          )
                        }
                      </div>
                    </div>
                  </>
                ) : (
                  <div
                    className="
                      rounded-xl
                      border
                      border-slate-700
                      bg-[#07111c]
                      p-8
                      text-sm
                      text-slate-500
                    "
                  >
                    Analyze a Suricata flow to
                    display the Isolation Forest
                    result, anomaly score and
                    extracted feature vector.
                  </div>
                )
              }
            </div>
          </div>
        </section>


        {/* ARCHITECTURE INFO */}

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
              Supervised Model
            </p>

            <p
              className="
                mt-3
                text-lg
                font-semibold
              "
            >
              Random Forest
            </p>

            <p
              className="
                mt-2
                text-sm
                text-slate-400
              "
            >
              CICIDS2017 · 78 features ·
              5 traffic classes
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
              Unsupervised Model
            </p>

            <p
              className="
                mt-3
                text-lg
                font-semibold
              "
            >
              Isolation Forest
            </p>

            <p
              className="
                mt-2
                text-sm
                text-slate-400
              "
            >
              Real-time Suricata flow
              anomaly detection
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
              Attack Classes
            </p>

            <p
              className="
                mt-3
                text-sm
                leading-7
                text-slate-300
              "
            >
              BENIGN · DDoS · PortScan ·
              FTP-Patator · SSH-Patator
            </p>
          </div>
        </section>

      </div>
    </main>
  );
}