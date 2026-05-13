# Home And Client Console Flow

Status: draft
Area: Auth/UI
Last Updated: 2026-05-13

## Goal

Make the public home page and developer client console respond to the user's
authentication and permission state instead of showing anonymous onboarding
actions everywhere.

## Home Page

1. Anonymous visitors see public onboarding actions: register and login.
2. Signed-in users do not see register or login calls to action.
3. Signed-in users see account actions such as profile and logout.
4. Signed-in users with developer, admin, or root permissions can reach the
   developer dashboard from the home page.
5. Signed-in users with admin or root permissions can reach the admin
   dashboard from the home page.

## Header

1. The header keeps brand and primary navigation on the left.
2. Global utilities such as theme selection live in the right-side utility
   cluster.
3. Account actions are grouped under a compact account menu.
4. Mobile headers collapse lower-priority navigation into a menu.

## Create Client

1. Only users with developer-like access can create OAuth2/OIDC clients.
2. Client metadata is validated before persistence.
3. Redirect URIs and client URI values must be absolute HTTP(S) URLs.
4. Grant types, response types, scopes, and token endpoint auth method must
   match supported OIDC/OAuth2 values.
5. Newly generated client credentials are shown once after creation with
   copy-friendly technical values.

## Out Of Scope

- Permission request persistence for the admin dashboard.
- Profile mutation endpoints for nickname, email, password, and wallet state.
- Full client edit/delete/secret rotation workflows.
