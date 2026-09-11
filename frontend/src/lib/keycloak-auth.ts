"use client";

import keycloak from "./keycloak";

let initPromise: Promise<boolean> | null = null;

export function initKeycloak(): Promise<boolean> {
  if (initPromise) {
    console.log("[Keycloak] reusing init promise");
    return initPromise;
  }

  console.log("[Keycloak] init started");

  initPromise = keycloak
    .init({
      onLoad: "check-sso",
      pkceMethod: "S256",
      checkLoginIframe: false,
    })
    .then((authenticated) => {
      console.log(
        "[Keycloak] init completed:",
        authenticated,
      );

      return authenticated;
    })
    .catch((error) => {
      console.error(
        "[Keycloak] init failed:",
        error,
      );

      initPromise = null;
      throw error;
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
