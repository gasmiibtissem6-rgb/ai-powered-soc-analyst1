"use client";

import keycloak from "./keycloak";

let initPromise: Promise<boolean> | null = null;

export function initKeycloak(): Promise<boolean> {
  if (initPromise) {
    return initPromise;
  }

  initPromise = keycloak.init({
    onLoad: "check-sso",
    pkceMethod: "S256",
    checkLoginIframe: false,
  });

  return initPromise;
}

export async function loginWithKeycloak() {
  await initKeycloak();

  await keycloak.login({
    redirectUri: window.location.origin,
  });
}

export async function logoutFromKeycloak() {
  await initKeycloak();

  await keycloak.logout({
    redirectUri: `${window.location.origin}/login`,
  });
}

export function getKeycloakToken() {
  return keycloak.token ?? null;
}

export async function refreshKeycloakToken() {
  if (!keycloak.authenticated) {
    return false;
  }

  try {
    await keycloak.updateToken(30);
    return true;
  } catch {
    return false;
  }
}

export { keycloak };
