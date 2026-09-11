"use client";

import { useEffect, useState } from "react";
import { apiRequest } from "@/lib/api";
import { initKeycloak } from "@/lib/keycloak-auth";
import { useRouter } from "next/navigation";

type Metrics = {
  total_incidents: number;
  open_incidents?: number;
  resolved_incidents?: number;
  critical_incidents?: number;
};


type SeverityMetrics = {
  severity: string;
  count: number;
};

type SeverityMetricsResponse =
  | SeverityMetrics[]
  | Record<string, number>;

type Incident = {
  id: number;
  title: string;
  severity: string;
  status: string;
  source: string;
};



export default function DashboardPage() {

  const router = useRouter();

  const [metrics, setMetrics] =
    useState<Metrics | null>(null);


  const [severity, setSeverity] =
    useState<SeverityMetrics[]>([]);


  const [incidents, setIncidents] =
    useState<Incident[]>([]);


  const [loading, setLoading] =
    useState(true);




  useEffect(() => {


    async function load() {


      try {


        const authenticated =
          await initKeycloak();



        if (!authenticated) {

          return;

        }




        const metricsData =
          await apiRequest<Metrics>(
            "/metrics"
          );



        const severityData =
               await apiRequest<SeverityMetricsResponse>(
            "/metrics/severity"
  );



        const incidentsData =
          await apiRequest<Incident[]>(
            "/incidents"
          );



        setMetrics(metricsData);




        if (Array.isArray(severityData)) {


          setSeverity(
            severityData
          );


        } else {


          setSeverity(

            Object.entries(severityData).map(
              ([severity, count]) => ({

                severity,

                count: Number(count),

              })
            )

          );


        }




        setIncidents(
          incidentsData.slice(0, 5)
        );



      }
      catch(error) {


        console.error(
          "Dashboard loading error:",
          error
        );


      }
      finally {


        setLoading(false);


      }


    }



    load();



  }, []);






  if (loading) {


    return (

      <div className="p-10">

        Loading dashboard...

      </div>

    );

  }






  return (


    <main className="p-8 space-y-6">


      <h1 className="text-3xl font-bold">

        SOC Dashboard

      </h1>





      {/* KPI CARDS */}

      <section className="grid grid-cols-4 gap-5">



        <div className="border rounded-xl p-5">

          <h2 className="font-semibold">

            Total Incidents

          </h2>


          <p className="text-3xl mt-3">

            {metrics?.total_incidents ?? 0}

          </p>

        </div>






        <div className="border rounded-xl p-5">


          <h2 className="font-semibold">

            Open Incidents

          </h2>


          <p className="text-3xl mt-3">

            {metrics?.open_incidents ?? 0}

          </p>


        </div>






        <div className="border rounded-xl p-5">


          <h2 className="font-semibold">

            Critical

          </h2>


          <p className="text-3xl mt-3">

            {metrics?.critical_incidents ?? 0}

          </p>


        </div>






        <div className="border rounded-xl p-5">


          <h2 className="font-semibold">

            Resolved

          </h2>


          <p className="text-3xl mt-3">

            {metrics?.resolved_incidents ?? 0}

          </p>


        </div>



      </section>








      {/* RECENT INCIDENTS */}


      <section className="border rounded-xl p-6">


        <h2 className="text-xl font-bold">

          Recent Incidents

        </h2>




        <div className="mt-5 space-y-3">


          {
            incidents.map(
              (item) => (


                <div

key={item.id}

onClick={() =>
  router.push(`/incidents/${item.id}`)
}

className="
border 
rounded-lg 
p-4 
flex 
justify-between 
items-center
cursor-pointer
hover:bg-gray-800
transition
"

>



                  <div>


                    <p className="font-semibold">

                      #{item.id} {item.title}

                    </p>



                    <p className="text-sm mt-1">

                      Source: {item.source}

                    </p>


                  </div>





                  <div className="text-right">


                    <p>

                      Severity:

                      <b className="ml-2">

                        {item.severity}

                      </b>


                    </p>




                    <p>

                      Status:

                      <b className="ml-2">

                        {item.status}

                      </b>


                    </p>



                  </div>



                </div>


              )
            )
          }



        </div>



      </section>








      {/* SEVERITY DISTRIBUTION */}


      <section className="border rounded-xl p-6">


        <h2 className="text-xl font-bold">

          Incident Severity Distribution

        </h2>





        <div className="mt-5 space-y-3">


          {
            severity.map(
              (item,index)=>(


                <div

                  key={index}

                  className="border rounded-lg p-3 flex justify-between"

                >


                  <span>

                    {item.severity}

                  </span>



                  <b>

                    {item.count}

                  </b>



                </div>


              )
            )
          }



        </div>



      </section>





    </main>


  );


}