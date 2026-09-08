"use client";

import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";

import { apiRequest } from "@/lib/api";
import {
  initKeycloak,
  loginWithKeycloak,
} from "@/lib/keycloak-auth";

type CurrentUser = {
  subject: string;
  email: string | null;
  full_name: string | null;
  roles: string[];
  source: string;
};

export default function LoginPage() {
  const router = useRouter();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;

    async function initializeAuthentication() {
      try {
        const authenticated = await initKeycloak();

        if (!active) {
          return;
        }

        if (!authenticated) {
          setLoading(false);
          return;
        }

        const user = await apiRequest<CurrentUser>("/auth/me");

        localStorage.removeItem("access_token");
        localStorage.setItem("soc_user", JSON.stringify(user));

        router.replace("/");
      } catch (err) {
        if (!active) {
          return;
        }

        localStorage.removeItem("access_token");
        localStorage.removeItem("soc_user");

        setError(
          err instanceof Error
            ? err.message
            : "Unable to initialize secure authentication.",
        );

        setLoading(false);
      }
    }

    void initializeAuthentication();

    return () => {
      active = false;
    };
  }, [router]);

  async function handleLogin() {
    setError("");
    setLoading(true);

    try {
      await loginWithKeycloak();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to start secure sign in.",
      );

      setLoading(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-card">
        <div className="login-logo">
          <div className="login-logo-icon">
            <ShieldCheck size={28} />
          </div>

          <div>
            <h1>AETHER SOC</h1>
            <p>AI-Powered SOC Analyst</p>
          </div>
        </div>

        <div className="login-heading">
          <h2>Analyst Login</h2>
          <p>
            Sign in securely through the SOC identity provider
            to access the Security Operations Center.
          </p>
        </div>

        {error && (
          <div className="login-error">
            {error}
          </div>
        )}

        <button
          className="login-button"
          type="button"
          disabled={loading}
          onClick={handleLogin}
        >
          {loading ? "Checking session..." : "Sign in with Keycloak"}
        </button>

        <div className="login-footer">
          <span className="status-dot-login" />
          Secure SOC Access · OIDC + PKCE
        </div>
      </section>
    </main>
  );
}
