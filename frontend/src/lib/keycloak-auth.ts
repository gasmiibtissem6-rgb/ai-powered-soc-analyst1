"use client";

import keycloak from "./keycloak";


declare global {
  var __socKeycloakInitPromise:
    Promise<boolean> | undefined;
}


function getInitPromise():
  Promise<boolean> | undefined {
  return (
    globalThis
      .__socKeycloakInitPromise
  );
}


function setInitPromise(
  promise: Promise<boolean>
) {
  globalThis
    .__socKeycloakInitPromise =
    promise;
}


export function initKeycloak():
  Promise<boolean> {
  const existingPromise =
    getInitPromise();

  if (existingPromise) {
    console.log(
      "[Keycloak] reusing init promise"
    );

    return existingPromise;
  }


  console.log(
    "[Keycloak] init started"
  );


  const promise =
    keycloak
      .init({
        onLoad: "check-sso",
        pkceMethod: "S256",
        checkLoginIframe: false,
      })
      .then(
        (authenticated) => {
          console.log(
            "[Keycloak] init completed:",
            authenticated
          );

          return authenticated;
        }
      )
      .catch(
        (error) => {
          console.error(
            "[Keycloak] init failed:",
            error
          );

          /*
           * IMPORTANT:
           *
           * Do not clear the init promise here.
           *
           * keycloak-js does not allow init()
           * to be called twice on the same
           * Keycloak instance.
           */
          throw error;
        }
      );


  setInitPromise(
    promise
  );

  return promise;
}


export async function loginWithKeycloak() {
  await initKeycloak();

  await keycloak.login({
    redirectUri:
      `${window.location.origin}/dashboard`,
  });
}


export async function logoutFromKeycloak() {
  await initKeycloak();

  await keycloak.logout({
    redirectUri:
      `${window.location.origin}/login`,
  });
}


export function getKeycloakToken() {
  return (
    keycloak.token ??
    null
  );
}


export async function refreshKeycloakToken() {
  await initKeycloak();

  if (
    !keycloak.authenticated
  ) {
    return false;
  }


  try {
    await keycloak.updateToken(
      30
    );

    return true;

  } catch (
    error
  ) {
    console.error(
      "[Keycloak] token refresh failed:",
      error
    );

    return false;
  }
}


export {
  keycloak,
};