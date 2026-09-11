"use client";

import {
  getKeycloakToken,
  refreshKeycloakToken,
} from "./keycloak-auth";

const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "https://soc.local";

export class ApiError extends Error {
  status: number;

  constructor(
    status: number,
    message: string,
  ) {
    super(message);

    this.name = "ApiError";
    this.status = status;
  }
}

export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> {

  // =====================================================
  // 1. REFRESH KEYCLOAK TOKEN
  // =====================================================

  await refreshKeycloakToken();


  // =====================================================
  // 2. PREPARE HEADERS
  // =====================================================

  const headers =
    new Headers(
      options.headers,
    );


  if (
    !headers.has("Content-Type") &&
    options.body
  ) {
    headers.set(
      "Content-Type",
      "application/json",
    );
  }


  // =====================================================
  // 3. KEYCLOAK TOKEN ONLY
  // =====================================================

  const token =
    getKeycloakToken();


  if (!token) {
    throw new ApiError(
      401,
      "No Keycloak access token available",
    );
  }


  headers.set(
    "Authorization",
    `Bearer ${token}`,
  );


  // =====================================================
  // 4. API REQUEST
  // =====================================================

  const response =
    await fetch(
      `${API_URL}${endpoint}`,
      {
        ...options,
        headers,
      },
    );


  // =====================================================
  // 5. HANDLE ERRORS
  // =====================================================

  if (!response.ok) {

    let message =
      `API request failed (${response.status})`;


    try {

      const data =
        await response.json();


      if (
        typeof data?.detail === "string"
      ) {
        message =
          data.detail;
      }

    } catch {
      // Keep generic error message.
    }


    throw new ApiError(
      response.status,
      message,
    );
  }


  // =====================================================
  // 6. EMPTY RESPONSE
  // =====================================================

  if (
    response.status === 204
  ) {
    return undefined as T;
  }


  // =====================================================
  // 7. JSON RESPONSE
  // =====================================================

  return (
    await response.json()
  ) as T;
}


export {
  API_URL,
};