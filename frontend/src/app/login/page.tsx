"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { LockKeyhole, Mail, ShieldCheck } from "lucide-react";
import { apiRequest } from "@/lib/api";

type TokenResponse = {
  access_token: string;
  token_type: string;
};

type UserResponse = {
  id: number;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
};

export default function LoginPage() {
  const router = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setError("");
    setLoading(true);

    try {
      const token = await apiRequest<TokenResponse>("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
        }),
      });

      localStorage.setItem("access_token", token.access_token);

      const user = await apiRequest<UserResponse>("/auth/me");

      localStorage.setItem("soc_user", JSON.stringify(user));

      router.push("/");
    } catch (err) {
      localStorage.removeItem("access_token");
      localStorage.removeItem("soc_user");

      setError(
        err instanceof Error
          ? err.message
          : "Unable to sign in."
      );
    } finally {
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
            Sign in to access the Security Operations Center.
          </p>
        </div>

        <form onSubmit={handleSubmit}>
          <label htmlFor="email">Email</label>

          <div className="login-input">
            <Mail size={18} />

            <input
              id="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="analyst@example.com"
              autoComplete="email"
              required
            />
          </div>

          <label htmlFor="password">Password</label>

          <div className="login-input">
            <LockKeyhole size={18} />

            <input
              id="password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter your password"
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <div className="login-error">
              {error}
            </div>
          )}

          <button
            className="login-button"
            type="submit"
            disabled={loading}
          >
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <div className="login-footer">
          <span className="status-dot-login" />
          Secure SOC Access
        </div>
      </section>
    </main>
  );
}