"use client";

import {
  useEffect,
  useState,
} from "react";

import { useRouter } from "next/navigation";

import { apiRequest } from "@/lib/api";
import { initKeycloak } from "@/lib/keycloak-auth";


type Provider =
  | "abuseipdb"
  | "virustotal"
  | "otx";


type IOCType =
  | "ip"
  | "domain"
  | "url"
  | "hash";


type ThreatIntelligenceItem = {
  ioc_type: string;
  value: string;

  scope?: string | null;
  hash_type?: string | null;

  providers: Record<
    string,
    unknown
  >;
};


type IncidentThreatIntelligence = {
  incident_id: number;

  source?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;

  extracted_iocs: {
    ips: string[];
    domains: string[];
    urls: string[];
    hashes: unknown[];
  };

  ioc_summary: {
    ips: number;
    domains: number;
    urls: number;
    hashes: number;
  };

  ioc_count: number;

  threat_intelligence:
    ThreatIntelligenceItem[];
};


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


function providerLabel(
  provider: Provider
) {
  switch (provider) {
    case "abuseipdb":
      return "AbuseIPDB";

    case "virustotal":
      return "VirusTotal";

    case "otx":
      return "AlienVault OTX";
  }
}


function buildEndpoint(
  provider: Provider,
  iocType: IOCType,
  value: string
) {
  const encoded =
    encodeURIComponent(
      value.trim()
    );


  if (
    provider === "abuseipdb"
  ) {
    return (
      `/threat-intelligence/ip/${encoded}`
    );
  }


  if (
    provider === "virustotal"
  ) {

    if (
      iocType === "url"
    ) {
      return (
        "/threat-intelligence/virustotal/url"
      );
    }

    return (
      `/threat-intelligence/virustotal/${iocType}/${encoded}`
    );

  }


  if (
    iocType === "url"
  ) {
    return (
      "/threat-intelligence/otx/url"
    );
  }


  return (
    `/threat-intelligence/otx/${iocType}/${encoded}`
  );
}


export default function ThreatIntelligencePage() {

  const router =
    useRouter();


  const [loading, setLoading] =
    useState(true);


  const [error, setError] =
    useState<string | null>(
      null
    );


  // =====================================================
  // MANUAL IOC LOOKUP
  // =====================================================

  const [provider, setProvider] =
    useState<Provider>(
      "abuseipdb"
    );


  const [iocType, setIOCType] =
    useState<IOCType>(
      "ip"
    );


  const [iocValue, setIOCValue] =
    useState("");


  const [
    lookupLoading,
    setLookupLoading,
  ] =
    useState(false);


  const [
    lookupResult,
    setLookupResult,
  ] =
    useState<unknown>(
      null
    );


  // =====================================================
  // TEXT ANALYSIS
  // =====================================================

  const [analysisText, setAnalysisText] =
    useState("");


  const [
    textAnalysisLoading,
    setTextAnalysisLoading,
  ] =
    useState(false);


  const [
    textAnalysisResult,
    setTextAnalysisResult,
  ] =
    useState<unknown>(
      null
    );


  // =====================================================
  // INCIDENT ANALYSIS
  // =====================================================

  const [
    incidentId,
    setIncidentId,
  ] =
    useState("");


  const [
    incidentLoading,
    setIncidentLoading,
  ] =
    useState(false);


  const [
    incidentResult,
    setIncidentResult,
  ] =
    useState<
      IncidentThreatIntelligence | null
    >(
      null
    );


  // =====================================================
  // AUTHENTICATION
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


      } catch (requestError) {

        console.error(
          "Unable to initialize Threat Intelligence page:",
          requestError
        );


        if (!active) {
          return;
        }


        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to initialize Threat Intelligence"
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
  // PROVIDER CHANGE
  // =====================================================

  function changeProvider(
    nextProvider: Provider
  ) {

    setProvider(
      nextProvider
    );


    if (
      nextProvider === "abuseipdb"
    ) {

      setIOCType(
        "ip"
      );

    }

  }


  // =====================================================
  // MANUAL IOC LOOKUP
  // =====================================================

  async function runLookup() {

    const value =
      iocValue.trim();


    if (!value) {

      setError(
        "Enter an IOC value before running Threat Intelligence."
      );

      return;
    }


    try {

      setLookupLoading(
        true
      );

      setError(
        null
      );

      setLookupResult(
        null
      );


      const endpoint =
        buildEndpoint(
          provider,
          iocType,
          value
        );


      let result: unknown;


      if (
        iocType === "url" &&
        provider !== "abuseipdb"
      ) {

        result =
          await apiRequest<unknown>(
            endpoint,
            {
              method: "POST",

              body:
                JSON.stringify({
                  url: value,
                }),
            }
          );

      } else {

        result =
          await apiRequest<unknown>(
            endpoint
          );

      }


      setLookupResult(
        result
      );


    } catch (requestError) {

      console.error(
        "Threat Intelligence lookup failed:",
        requestError
      );


      setError(
        requestError instanceof Error
          ? requestError.message
          : "Threat Intelligence lookup failed"
      );


    } finally {

      setLookupLoading(
        false
      );

    }

  }


  // =====================================================
  // TEXT ANALYSIS
  // =====================================================

  async function runTextAnalysis() {

    const text =
      analysisText.trim();


    if (!text) {

      setError(
        "Enter security log text before analysis."
      );

      return;
    }


    try {

      setTextAnalysisLoading(
        true
      );

      setError(
        null
      );

      setTextAnalysisResult(
        null
      );


      const result =
        await apiRequest<unknown>(
          "/threat-intelligence/analyze",
          {
            method: "POST",

            body:
              JSON.stringify({
                text,
              }),
          }
        );


      setTextAnalysisResult(
        result
      );


    } catch (requestError) {

      console.error(
        "Threat Intelligence text analysis failed:",
        requestError
      );


      setError(
        requestError instanceof Error
          ? requestError.message
          : "Threat Intelligence text analysis failed"
      );


    } finally {

      setTextAnalysisLoading(
        false
      );

    }

  }


  // =====================================================
  // INCIDENT MULTI-PROVIDER ANALYSIS
  // =====================================================

  async function runIncidentAnalysis() {

    const normalizedId =
      Number(
        incidentId
      );


    if (
      !Number.isInteger(
        normalizedId
      ) ||
      normalizedId <= 0
    ) {

      setError(
        "Enter a valid incident ID."
      );

      return;
    }


    try {

      setIncidentLoading(
        true
      );

      setError(
        null
      );

      setIncidentResult(
        null
      );


      const result =
        await apiRequest<
          IncidentThreatIntelligence
        >(
          `/threat-intelligence/incident/${normalizedId}`
        );


      setIncidentResult(
        result
      );


    } catch (requestError) {

      console.error(
        "Incident Threat Intelligence analysis failed:",
        requestError
      );


      setError(
        requestError instanceof Error
          ? requestError.message
          : "Incident Threat Intelligence analysis failed"
      );


    } finally {

      setIncidentLoading(
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
          Loading Threat Intelligence...
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
              IOC Enrichment & Reputation Analysis
            </p>


            <h1
              className="
                mt-2
                text-3xl
                font-bold
              "
            >
              Threat Intelligence
            </h1>


            <p
              className="
                mt-2
                text-sm
                text-slate-400
              "
            >
              Analyze indicators using AbuseIPDB,
              VirusTotal and AlienVault OTX,
              or enrich every IOC associated with
              a SOC incident.
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


        {/* PROVIDERS */}

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
              border-cyan-500/30
              bg-[#0b1622]
              p-5
            "
          >
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Provider
            </p>

            <h2 className="mt-2 text-xl font-bold text-cyan-300">
              AbuseIPDB
            </h2>

            <p className="mt-2 text-sm text-slate-400">
              Public IP abuse reputation and
              confidence scoring.
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
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Provider
            </p>

            <h2 className="mt-2 text-xl font-bold text-violet-300">
              VirusTotal
            </h2>

            <p className="mt-2 text-sm text-slate-400">
              IP, domain, URL and file hash
              reputation analysis.
            </p>
          </div>


          <div
            className="
              rounded-xl
              border
              border-emerald-500/30
              bg-[#0b1622]
              p-5
            "
          >
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Provider
            </p>

            <h2 className="mt-2 text-xl font-bold text-emerald-300">
              AlienVault OTX
            </h2>

            <p className="mt-2 text-sm text-slate-400">
              Community threat intelligence,
              pulses and IOC reputation.
            </p>
          </div>

        </section>


        {/* MANUAL IOC LOOKUP */}

        <section
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
            Manual IOC Lookup
          </h2>


          <p
            className="
              mt-2
              text-sm
              text-slate-400
            "
          >
            Select a provider and inspect
            one indicator of compromise.
          </p>


          <div
            className="
              mt-5
              grid
              gap-4
              md:grid-cols-4
            "
          >

            <select
              value={
                provider
              }
              onChange={
                (event) =>
                  changeProvider(
                    event.target.value as Provider
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
              <option value="abuseipdb">
                AbuseIPDB
              </option>

              <option value="virustotal">
                VirusTotal
              </option>

              <option value="otx">
                AlienVault OTX
              </option>
            </select>


            <select
              value={
                iocType
              }
              disabled={
                provider === "abuseipdb"
              }
              onChange={
                (event) =>
                  setIOCType(
                    event.target.value as IOCType
                  )
              }
              className="
                rounded-lg
                border
                border-slate-600
                bg-[#07111c]
                px-3
                py-3
                disabled:opacity-50
              "
            >
              <option value="ip">
                IP Address
              </option>

              <option value="domain">
                Domain
              </option>

              <option value="url">
                URL
              </option>

              <option value="hash">
                File Hash
              </option>
            </select>


            <input
              value={
                iocValue
              }
              onChange={
                (event) =>
                  setIOCValue(
                    event.target.value
                  )
              }
              placeholder="Enter IOC value..."
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
                lookupLoading
              }
              onClick={
                () =>
                  void runLookup()
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
                lookupLoading
                  ? "Analyzing..."
                  : "Analyze IOC"
              }
            </button>

          </div>


          <p
            className="
              mt-3
              text-xs
              text-slate-500
            "
          >
            Active provider:{" "}
            <strong
              className="
                text-cyan-300
              "
            >
              {
                providerLabel(
                  provider
                )
              }
            </strong>
          </p>


          {
            lookupResult !== null && (

              <div
                className="
                  mt-5
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
                  Lookup Result
                </h3>


                <pre
                  className="
                    mt-4
                    max-h-[500px]
                    overflow-auto
                    whitespace-pre-wrap
                    break-words
                    text-xs
                    text-slate-300
                  "
                >
                  {
                    formatJson(
                      lookupResult
                    )
                  }
                </pre>

              </div>

            )
          }

        </section>


        {/* INCIDENT MULTI PROVIDER */}

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
            Incident Multi-Provider Enrichment
          </h2>


          <p
            className="
              mt-2
              text-sm
              text-slate-400
            "
          >
            Extract IPs, domains, URLs and hashes
            from an incident and enrich them across
            all configured Threat Intelligence providers.
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
                incidentId
              }
              onChange={
                (event) =>
                  setIncidentId(
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
                incidentLoading
              }
              onClick={
                () =>
                  void runIncidentAnalysis()
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
                incidentLoading
                  ? "Enriching..."
                  : "Analyze Incident"
              }
            </button>

          </div>


          {
            incidentResult && (

              <div
                className="
                  mt-6
                  space-y-5
                "
              >


                {/* SUMMARY */}

                <div
                  className="
                    grid
                    gap-4
                    sm:grid-cols-2
                    xl:grid-cols-5
                  "
                >

                  <div className="rounded-lg border border-slate-700 bg-[#07111c] p-4">
                    <p className="text-xs uppercase text-slate-500">
                      Incident
                    </p>

                    <p className="mt-2 text-2xl font-bold text-cyan-300">
                      #
                      {
                        incidentResult.incident_id
                      }
                    </p>
                  </div>


                  <div className="rounded-lg border border-slate-700 bg-[#07111c] p-4">
                    <p className="text-xs uppercase text-slate-500">
                      IPs
                    </p>

                    <p className="mt-2 text-2xl font-bold">
                      {
                        incidentResult.ioc_summary.ips
                      }
                    </p>
                  </div>


                  <div className="rounded-lg border border-slate-700 bg-[#07111c] p-4">
                    <p className="text-xs uppercase text-slate-500">
                      Domains
                    </p>

                    <p className="mt-2 text-2xl font-bold">
                      {
                        incidentResult.ioc_summary.domains
                      }
                    </p>
                  </div>


                  <div className="rounded-lg border border-slate-700 bg-[#07111c] p-4">
                    <p className="text-xs uppercase text-slate-500">
                      URLs
                    </p>

                    <p className="mt-2 text-2xl font-bold">
                      {
                        incidentResult.ioc_summary.urls
                      }
                    </p>
                  </div>


                  <div className="rounded-lg border border-slate-700 bg-[#07111c] p-4">
                    <p className="text-xs uppercase text-slate-500">
                      Hashes
                    </p>

                    <p className="mt-2 text-2xl font-bold">
                      {
                        incidentResult.ioc_summary.hashes
                      }
                    </p>
                  </div>

                </div>


                {/* IOC RESULTS */}

                {
                  incidentResult
                    .threat_intelligence
                    .length === 0 ? (

                    <div
                      className="
                        rounded-lg
                        border
                        border-slate-700
                        bg-[#07111c]
                        p-5
                        text-sm
                        text-slate-400
                      "
                    >
                      No indicators were extracted
                      from this incident.
                    </div>

                  ) : (

                    <div
                      className="
                        space-y-4
                      "
                    >

                      {
                        incidentResult
                          .threat_intelligence
                          .map(
                            (
                              item,
                              index
                            ) => (

                              <div
                                key={
                                  `${item.ioc_type}-${item.value}-${index}`
                                }
                                className="
                                  rounded-lg
                                  border
                                  border-slate-700
                                  bg-[#07111c]
                                  p-5
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

                                    <span
                                      className="
                                        rounded-full
                                        border
                                        border-cyan-500/40
                                        bg-cyan-500/10
                                        px-2.5
                                        py-1
                                        text-xs
                                        uppercase
                                        text-cyan-300
                                      "
                                    >
                                      {
                                        item.ioc_type
                                      }
                                    </span>


                                    <p
                                      className="
                                        mt-3
                                        break-all
                                        font-mono
                                        text-sm
                                        text-slate-200
                                      "
                                    >
                                      {
                                        item.value
                                      }
                                    </p>

                                  </div>


                                  {
                                    item.scope && (

                                      <span
                                        className="
                                          text-sm
                                          text-slate-400
                                        "
                                      >
                                        Scope:{" "}
                                        <strong
                                          className="
                                            text-slate-200
                                          "
                                        >
                                          {
                                            item.scope
                                          }
                                        </strong>
                                      </span>

                                    )
                                  }

                                </div>


                                <div
                                  className="
                                    mt-5
                                    grid
                                    gap-4
                                    lg:grid-cols-2
                                    xl:grid-cols-4
                                  "
                                >

                                  {
                                    Object.entries(
                                      item.providers
                                    ).map(
                                      ([
                                        providerName,
                                        providerResult,
                                      ]) => (

                                        <div
                                          key={
                                            providerName
                                          }
                                          className="
                                            rounded-lg
                                            border
                                            border-slate-800
                                            p-4
                                          "
                                        >

                                          <h4
                                            className="
                                              font-semibold
                                              capitalize
                                              text-cyan-300
                                            "
                                          >
                                            {
                                              providerName
                                            }
                                          </h4>


                                          <pre
                                            className="
                                              mt-3
                                              max-h-[300px]
                                              overflow-auto
                                              whitespace-pre-wrap
                                              break-words
                                              text-xs
                                              text-slate-400
                                            "
                                          >
                                            {
                                              formatJson(
                                                providerResult
                                              )
                                            }
                                          </pre>

                                        </div>

                                      )
                                    )
                                  }

                                </div>

                              </div>

                            )
                          )
                      }

                    </div>

                  )
                }

              </div>

            )
          }

        </section>


        {/* TEXT ANALYSIS */}

        <section
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
            Analyze Security Text
          </h2>


          <p
            className="
              mt-2
              text-sm
              text-slate-400
            "
          >
            Extract IPv4 indicators from logs or
            security text and inspect them with AbuseIPDB.
          </p>


          <textarea
            value={
              analysisText
            }
            onChange={
              (event) =>
                setAnalysisText(
                  event.target.value
                )
            }
            placeholder="Paste alert, log or security event text here..."
            className="
              mt-5
              min-h-[160px]
              w-full
              rounded-lg
              border
              border-slate-600
              bg-[#07111c]
              p-4
              outline-none
              focus:border-cyan-500
            "
          />


          <button
            type="button"
            disabled={
              textAnalysisLoading
            }
            onClick={
              () =>
                void runTextAnalysis()
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
              textAnalysisLoading
                ? "Analyzing..."
                : "Analyze Text"
            }
          </button>


          {
            textAnalysisResult !== null && (

              <div
                className="
                  mt-5
                  rounded-lg
                  border
                  border-slate-700
                  bg-[#07111c]
                  p-4
                "
              >

                <pre
                  className="
                    max-h-[500px]
                    overflow-auto
                    whitespace-pre-wrap
                    break-words
                    text-xs
                    text-slate-300
                  "
                >
                  {
                    formatJson(
                      textAnalysisResult
                    )
                  }
                </pre>

              </div>

            )
          }

        </section>

      </div>

    </main>

  );

}