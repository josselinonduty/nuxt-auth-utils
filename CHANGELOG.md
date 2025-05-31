# Changelog


## v0.6.1

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.6.0...v0.6.1)

## v0.6.0


### 🚀 Enhancements

- Allow users to define custom session factory + types ([#2](https://github.com/atinux/nuxt-auth-utils/pull/2))
- Added google as oauth provider ([#3](https://github.com/atinux/nuxt-auth-utils/pull/3))
- Added twitch as supported oauth provider ([#5](https://github.com/atinux/nuxt-auth-utils/pull/5))
- Added auth0 as oauth provider ([#6](https://github.com/atinux/nuxt-auth-utils/pull/6))
- Added discord auth provider ([#7](https://github.com/atinux/nuxt-auth-utils/pull/7))
- Added oauth battle.net ([#11](https://github.com/atinux/nuxt-auth-utils/pull/11))
- Refactor login buttons to use dropdown ([#14](https://github.com/atinux/nuxt-auth-utils/pull/14))
- Add max_age param for auth0 ([#26](https://github.com/atinux/nuxt-auth-utils/pull/26))
- Added Microsoft as oauth provider ([#8](https://github.com/atinux/nuxt-auth-utils/pull/8))
- Added linkedIn auth provider ([#13](https://github.com/atinux/nuxt-auth-utils/pull/13))
- Add sessionHooks to extend user sessions ([c470319](https://github.com/atinux/nuxt-auth-utils/commit/c470319))
- Added keycloak as oauth provider ([#23](https://github.com/atinux/nuxt-auth-utils/pull/23))
- Add auth0 connection parameter to config ([#39](https://github.com/atinux/nuxt-auth-utils/pull/39))
- Added aws cognito provider ([#36](https://github.com/atinux/nuxt-auth-utils/pull/36))
- Add replaceUserSession() ([#44](https://github.com/atinux/nuxt-auth-utils/pull/44))
- Add authorizationParams in oauth config ([#56](https://github.com/atinux/nuxt-auth-utils/pull/56))
- Generate NUXT_SESSION_PASSWORD and throw if not set in production ([de890ed](https://github.com/atinux/nuxt-auth-utils/commit/de890ed))
- Add `redirectUrl` to OAuthMicrosoftConfig for HTTP vs HTTPS Handling ([50ba6fe](https://github.com/atinux/nuxt-auth-utils/commit/50ba6fe))
- Add opts to requireUserSession for error message and status code customization ([015e847](https://github.com/atinux/nuxt-auth-utils/commit/015e847))
- Add facebook OAuth provider ([777d8b2](https://github.com/atinux/nuxt-auth-utils/commit/777d8b2))
- Add fields support to facebook provider ([8e53936](https://github.com/atinux/nuxt-auth-utils/commit/8e53936))
- ⚠️  Support hybrid rendering ([#104](https://github.com/atinux/nuxt-auth-utils/pull/104))
- Add steam as supported oauth provider ([c8b02d0](https://github.com/atinux/nuxt-auth-utils/commit/c8b02d0))
- Add paypal as supported oauth provider ([57ea01e](https://github.com/atinux/nuxt-auth-utils/commit/57ea01e))
- Add x(formerly twitter) as supported oauth provider ([a0be1f2](https://github.com/atinux/nuxt-auth-utils/commit/a0be1f2))
- Add xsuaa provider ([9afb9eb](https://github.com/atinux/nuxt-auth-utils/commit/9afb9eb))
- X/Twitter email requirement enhancement ([65d6324](https://github.com/atinux/nuxt-auth-utils/commit/65d6324))
- Add yandex oauth ([22bd974](https://github.com/atinux/nuxt-auth-utils/commit/22bd974))
- Support `NUXT_OAUTH_MICROSOFT_REDIRECT_URL` ([9979f0d](https://github.com/atinux/nuxt-auth-utils/commit/9979f0d))
- Add support nitro prefix env ([58ebf85](https://github.com/atinux/nuxt-auth-utils/commit/58ebf85))
- Support redirectURL config for all providers ([cdca787](https://github.com/atinux/nuxt-auth-utils/commit/cdca787))
- Cognito oauth support custom domain ([4ad11a4](https://github.com/atinux/nuxt-auth-utils/commit/4ad11a4))
- Add tiktok provider ([c1b1f44](https://github.com/atinux/nuxt-auth-utils/commit/c1b1f44))
- Add Gitlab provider ([fec746f](https://github.com/atinux/nuxt-auth-utils/commit/fec746f))
- Add instagram provider ([3bd553c](https://github.com/atinux/nuxt-auth-utils/commit/3bd553c))
- Add vk provider ([6581f12](https://github.com/atinux/nuxt-auth-utils/commit/6581f12))
- Add support for private data & config argument ([#171](https://github.com/atinux/nuxt-auth-utils/pull/171))
- Add Dropbox as supported oauth provider ([#183](https://github.com/atinux/nuxt-auth-utils/pull/183))
- ⚠️  Call `fetch` hook if session is not empty instead of user defined ([#188](https://github.com/atinux/nuxt-auth-utils/pull/188))
- ⚠️  Rename `oauth<Provider>EventHandler` to`defineOAuth<Provider>EventHandler` ([#189](https://github.com/atinux/nuxt-auth-utils/pull/189))
- Add `hashPassword` & `verifyPassword` server utils ([0c4d050](https://github.com/atinux/nuxt-auth-utils/commit/0c4d050))
- Webauthn (passkey) support ([a90b173](https://github.com/atinux/nuxt-auth-utils/commit/a90b173))
- Add polar provider ([2682bcb](https://github.com/atinux/nuxt-auth-utils/commit/2682bcb))
- ClearUserSession takes config arg as well ([69eaf42](https://github.com/atinux/nuxt-auth-utils/commit/69eaf42))
- Add linear provider ([c1291cd](https://github.com/atinux/nuxt-auth-utils/commit/c1291cd))
- Zitadel provider implementation ([d4c0b5a](https://github.com/atinux/nuxt-auth-utils/commit/d4c0b5a))
- Add authentik provider ([33686af](https://github.com/atinux/nuxt-auth-utils/commit/33686af))
- Forward set-cookie header for `useUserSession().clear()` ([#282](https://github.com/atinux/nuxt-auth-utils/pull/282))
- Add workos oauth provider ([bfa2a88](https://github.com/atinux/nuxt-auth-utils/commit/bfa2a88))
- Add seznam oauth provider ([#285](https://github.com/atinux/nuxt-auth-utils/pull/285))
- **webauthn:** Add event to validateUser to track authenticated users ([#287](https://github.com/atinux/nuxt-auth-utils/pull/287))
- Adding `organization_id` option for WorkOS provider ([677b226](https://github.com/atinux/nuxt-auth-utils/commit/677b226))
- Add strava oauth provider ([96363b2](https://github.com/atinux/nuxt-auth-utils/commit/96363b2))
- Keycloak internal server URL ([ac61ae5](https://github.com/atinux/nuxt-auth-utils/commit/ac61ae5))
- **cognito:** Integrate OpenID Connect discovery for improved OAuth flow ([7a01cc3](https://github.com/atinux/nuxt-auth-utils/commit/7a01cc3))
- Add hubspot provider ([1a79baf](https://github.com/atinux/nuxt-auth-utils/commit/1a79baf))
- Self-hosted Gitlab instances ([#323](https://github.com/atinux/nuxt-auth-utils/pull/323))
- Add Line OAuth provider ([#312](https://github.com/atinux/nuxt-auth-utils/pull/312))
- Add atlassian oauth-provider ([#307](https://github.com/atinux/nuxt-auth-utils/pull/307), [#308](https://github.com/atinux/nuxt-auth-utils/pull/308))
- Add support for websocket handler ([#327](https://github.com/atinux/nuxt-auth-utils/pull/327))
- Add apple provider ([#328](https://github.com/atinux/nuxt-auth-utils/pull/328))
- Set `email_verified` in `user` on GitHub provider ([#332](https://github.com/atinux/nuxt-auth-utils/pull/332))
- **composable:** Add `openInPopup(route, { width, height })` ([#336](https://github.com/atinux/nuxt-auth-utils/pull/336))
- Add Gitea Oauth Provider ([#335](https://github.com/atinux/nuxt-auth-utils/pull/335))
- **session:** Add generated session id ([#338](https://github.com/atinux/nuxt-auth-utils/pull/338))
- Add bluesky as a provider ([#281](https://github.com/atinux/nuxt-auth-utils/pull/281))
- Custom params for Keycloak ([#355](https://github.com/atinux/nuxt-auth-utils/pull/355))
- Add LiveChat OAuth ([#376](https://github.com/atinux/nuxt-auth-utils/pull/376))
- Add azure b2c oauth provider ([#362](https://github.com/atinux/nuxt-auth-utils/pull/362))
- Add kick provider ([#360](https://github.com/atinux/nuxt-auth-utils/pull/360))
- Support GitHub Enterprise Server and GHE.com ([#383](https://github.com/atinux/nuxt-auth-utils/pull/383))
- Add Salesforce, Slack and Heroku OAuth providers ([#382](https://github.com/atinux/nuxt-auth-utils/pull/382))
- Add support for authorization parameters and ensure state param is included from query when present in Facebook & Microsoft OAuth ([#386](https://github.com/atinux/nuxt-auth-utils/pull/386))
- Add rauthy provider ([3e3cd61](https://github.com/atinux/nuxt-auth-utils/commit/3e3cd61))
- Update package name to include rauthy prefix ([a8f46df](https://github.com/atinux/nuxt-auth-utils/commit/a8f46df))

### 🔥 Performance

- ⚠️  One export per provider for tree-shaking ([4f98b53](https://github.com/atinux/nuxt-auth-utils/commit/4f98b53))

### 🩹 Fixes

- Workaround for addServerImportsDir not working ([5a189df](https://github.com/atinux/nuxt-auth-utils/commit/5a189df))
- Don't log warning about password when preparing types ([804057b](https://github.com/atinux/nuxt-auth-utils/commit/804057b))
- Import useRuntimeConfig ([bdbb4b8](https://github.com/atinux/nuxt-auth-utils/commit/bdbb4b8))
- Use import presets ([f16ebc9](https://github.com/atinux/nuxt-auth-utils/commit/f16ebc9))
- **oauth:** Add generic OAuthConfig type ([#18](https://github.com/atinux/nuxt-auth-utils/pull/18))
- Avoid infinite loop with latest Nuxt ([93b949d](https://github.com/atinux/nuxt-auth-utils/commit/93b949d))
- Add audience to auth0 runtime config types ([#27](https://github.com/atinux/nuxt-auth-utils/pull/27))
- Correct arguments for hooks ([6e0193e](https://github.com/atinux/nuxt-auth-utils/commit/6e0193e))
- Replace encoded space characters with regular spaces ([#40](https://github.com/atinux/nuxt-auth-utils/pull/40))
- **google:** Remove `redirectUrl` type ([#52](https://github.com/atinux/nuxt-auth-utils/pull/52))
- UserSession user type augmentation ([#54](https://github.com/atinux/nuxt-auth-utils/pull/54))
- User session types ([#55](https://github.com/atinux/nuxt-auth-utils/pull/55))
- Leverage runtimeConfig to check password ([7c23543](https://github.com/atinux/nuxt-auth-utils/commit/7c23543))
- Leverage NUXT_SESSION_PASSWORD provided at runtime ([4932959](https://github.com/atinux/nuxt-auth-utils/commit/4932959))
- **types:** Narrowed session type passed to fetch session hook ([77c82e7](https://github.com/atinux/nuxt-auth-utils/commit/77c82e7))
- Avoid duplicate trigger of session fetch hook due to request retry ([5fac9a1](https://github.com/atinux/nuxt-auth-utils/commit/5fac9a1))
- Always return 200 for session endpoint ([#130](https://github.com/atinux/nuxt-auth-utils/pull/130))
- Add missing session in AuthState ([3e39727](https://github.com/atinux/nuxt-auth-utils/commit/3e39727))
- Fetch session directly when ssr disabled ([#151](https://github.com/atinux/nuxt-auth-utils/pull/151))
- Paypal tokens request requires encoded `redirect_uri` ([8bf3b0b](https://github.com/atinux/nuxt-auth-utils/commit/8bf3b0b))
- Ensure plugin declaration files are emitted ([#170](https://github.com/atinux/nuxt-auth-utils/pull/170))
- UserSession secure type augmentation ([#181](https://github.com/atinux/nuxt-auth-utils/pull/181))
- **steam:** Improve open id validation ([#184](https://github.com/atinux/nuxt-auth-utils/pull/184))
- Fetch hook is called even is user is not set ([#209](https://github.com/atinux/nuxt-auth-utils/pull/209))
- `useWebAuthn` composable registration & fix `allowCredentials` / `excludeCredentials` option ([#266](https://github.com/atinux/nuxt-auth-utils/pull/266))
- **composable:** Use same context for `clear` and `fetch` ([#278](https://github.com/atinux/nuxt-auth-utils/pull/278))
- Seznam config ([90d0d18](https://github.com/atinux/nuxt-auth-utils/commit/90d0d18))
- **instagram:** Oauth provider ([192e0e7](https://github.com/atinux/nuxt-auth-utils/commit/192e0e7))
- Make sure the required env is checked ([#306](https://github.com/atinux/nuxt-auth-utils/pull/306))
- Add discord oauth error ([#316](https://github.com/atinux/nuxt-auth-utils/pull/316))
- Normalise errors when user not accessible ([c98ea5d](https://github.com/atinux/nuxt-auth-utils/commit/c98ea5d))
- Dammit corepack ([239f97a](https://github.com/atinux/nuxt-auth-utils/commit/239f97a))
- **microsoft:** Fix duplicated scopes ([#331](https://github.com/atinux/nuxt-auth-utils/pull/331))
- **bluesky:** Use local map for session storing ([#340](https://github.com/atinux/nuxt-auth-utils/pull/340))
- Move atproto util in runtime ([ff2ddc9](https://github.com/atinux/nuxt-auth-utils/commit/ff2ddc9))
- Import useError ([b7e078d](https://github.com/atinux/nuxt-auth-utils/commit/b7e078d))
- Verify steam credentials ([#365](https://github.com/atinux/nuxt-auth-utils/pull/365))
- Remove `ohash` dependency ([#377](https://github.com/atinux/nuxt-auth-utils/pull/377))
- **oauth, apple:** Return tokens in response ([#373](https://github.com/atinux/nuxt-auth-utils/pull/373))
- **oauth, facebook:** Prevent duplication of config.fields and config.scope in defu merge ([#375](https://github.com/atinux/nuxt-auth-utils/pull/375))
- Explicit Return Type on getUserSession ([#379](https://github.com/atinux/nuxt-auth-utils/pull/379))

### 💅 Refactors

- Use `useSession` generic rather than assertion ([#4](https://github.com/atinux/nuxt-auth-utils/pull/4))
- Replace ofetch with $fetch ([a7df1b5](https://github.com/atinux/nuxt-auth-utils/commit/a7df1b5))
- Handle missing configuration error ([5675aaf](https://github.com/atinux/nuxt-auth-utils/commit/5675aaf))
- Handle access token error response ([a1b3fbb](https://github.com/atinux/nuxt-auth-utils/commit/a1b3fbb))
- Request token ([925f688](https://github.com/atinux/nuxt-auth-utils/commit/925f688))

### 📖 Documentation

- Update readme ([06f1504](https://github.com/atinux/nuxt-auth-utils/commit/06f1504))
- Add demo ([cbc8b7a](https://github.com/atinux/nuxt-auth-utils/commit/cbc8b7a))
- Use consistent reference to module ([13daa78](https://github.com/atinux/nuxt-auth-utils/commit/13daa78))
- Add LinkedIn in providers ([c9b9925](https://github.com/atinux/nuxt-auth-utils/commit/c9b9925))
- Update badge colors ([ff868a6](https://github.com/atinux/nuxt-auth-utils/commit/ff868a6))
- Use new nuxi module add command in installation ([d64b9d3](https://github.com/atinux/nuxt-auth-utils/commit/d64b9d3))
- Improve readme ([00c8287](https://github.com/atinux/nuxt-auth-utils/commit/00c8287))
- Removed reference to /api in readme ([#77](https://github.com/atinux/nuxt-auth-utils/pull/77))
- Fix typos ([149448a](https://github.com/atinux/nuxt-auth-utils/commit/149448a))
- Include SSR instructions in the README, fixes #97 ([#99](https://github.com/atinux/nuxt-auth-utils/pull/99), [#97](https://github.com/atinux/nuxt-auth-utils/issues/97))
- Update readme ([7a4dcfb](https://github.com/atinux/nuxt-auth-utils/commit/7a4dcfb))
- Add X in readme ([b452d60](https://github.com/atinux/nuxt-auth-utils/commit/b452d60))
- Add TS signature ([04a5d88](https://github.com/atinux/nuxt-auth-utils/commit/04a5d88))
- Add note about dependencies ([67b5542](https://github.com/atinux/nuxt-auth-utils/commit/67b5542))
- Fix event handler name in example ([a4cfa89](https://github.com/atinux/nuxt-auth-utils/commit/a4cfa89))
- Update nitro version ([848cebe](https://github.com/atinux/nuxt-auth-utils/commit/848cebe))
- Fix typo ([8d3af7e](https://github.com/atinux/nuxt-auth-utils/commit/8d3af7e))
- Add note about cookie size ([a725436](https://github.com/atinux/nuxt-auth-utils/commit/a725436))
- Add note to readme about session API route ([ddf38c1](https://github.com/atinux/nuxt-auth-utils/commit/ddf38c1))
- Typo ([c16d014](https://github.com/atinux/nuxt-auth-utils/commit/c16d014))
- Update links ([2ed5e17](https://github.com/atinux/nuxt-auth-utils/commit/2ed5e17))
- Improvement ([3bd76b0](https://github.com/atinux/nuxt-auth-utils/commit/3bd76b0))
- Set webauthn version to v10 ([ca151c7](https://github.com/atinux/nuxt-auth-utils/commit/ca151c7))
- Fix typo ([#251](https://github.com/atinux/nuxt-auth-utils/pull/251))
- Typo ([8b132e4](https://github.com/atinux/nuxt-auth-utils/commit/8b132e4))
- Improve example ([9d191a1](https://github.com/atinux/nuxt-auth-utils/commit/9d191a1))
- Wrong var name in README.md ([#345](https://github.com/atinux/nuxt-auth-utils/pull/345))
- Update readme file to fix path to OAuth provider ([9d816a8](https://github.com/atinux/nuxt-auth-utils/commit/9d816a8))

### 🏡 Chore

- Init ([19caed2](https://github.com/atinux/nuxt-auth-utils/commit/19caed2))
- Add runtime config ([9013484](https://github.com/atinux/nuxt-auth-utils/commit/9013484))
- V0 ([18ea43a](https://github.com/atinux/nuxt-auth-utils/commit/18ea43a))
- Init ([9b75953](https://github.com/atinux/nuxt-auth-utils/commit/9b75953))
- **release:** V0.0.1 ([fd5a2c1](https://github.com/atinux/nuxt-auth-utils/commit/fd5a2c1))
- **release:** V0.0.2 ([f01b412](https://github.com/atinux/nuxt-auth-utils/commit/f01b412))
- Remove `.nuxtrc` ([3f96e97](https://github.com/atinux/nuxt-auth-utils/commit/3f96e97))
- Add type testing script ([e9ffa5e](https://github.com/atinux/nuxt-auth-utils/commit/e9ffa5e))
- Move playground into workspace ([bd8108c](https://github.com/atinux/nuxt-auth-utils/commit/bd8108c))
- Add playground type test ([74f452c](https://github.com/atinux/nuxt-auth-utils/commit/74f452c))
- **release:** V0.0.3 ([9d1342c](https://github.com/atinux/nuxt-auth-utils/commit/9d1342c))
- Add comment ([1923dcc](https://github.com/atinux/nuxt-auth-utils/commit/1923dcc))
- **release:** V0.0.4 ([2bc6f9a](https://github.com/atinux/nuxt-auth-utils/commit/2bc6f9a))
- **release:** V0.0.5 ([86226ad](https://github.com/atinux/nuxt-auth-utils/commit/86226ad))
- Update deps ([05f4a9c](https://github.com/atinux/nuxt-auth-utils/commit/05f4a9c))
- **release:** V0.0.6 ([4eb4f25](https://github.com/atinux/nuxt-auth-utils/commit/4eb4f25))
- Add SameSite=lax ([1b296e2](https://github.com/atinux/nuxt-auth-utils/commit/1b296e2))
- **release:** V0.0.7 ([5316d10](https://github.com/atinux/nuxt-auth-utils/commit/5316d10))
- **playground:** Better with right title ([97a3ad3](https://github.com/atinux/nuxt-auth-utils/commit/97a3ad3))
- **release:** V0.0.8 ([79f7ce7](https://github.com/atinux/nuxt-auth-utils/commit/79f7ce7))
- **release:** V0.0.9 ([36cadda](https://github.com/atinux/nuxt-auth-utils/commit/36cadda))
- Update deps ([bb3a510](https://github.com/atinux/nuxt-auth-utils/commit/bb3a510))
- **release:** V0.0.10 ([c60fde7](https://github.com/atinux/nuxt-auth-utils/commit/c60fde7))
- **release:** V0.0.11 ([b52ed08](https://github.com/atinux/nuxt-auth-utils/commit/b52ed08))
- **release:** V0.0.12 ([a74e7f4](https://github.com/atinux/nuxt-auth-utils/commit/a74e7f4))
- Rename session from verify to fetch ([10694e9](https://github.com/atinux/nuxt-auth-utils/commit/10694e9))
- **release:** V0.0.13 ([e344c98](https://github.com/atinux/nuxt-auth-utils/commit/e344c98))
- Test bundler module resolution ([#32](https://github.com/atinux/nuxt-auth-utils/pull/32))
- Update deps ([9d6b258](https://github.com/atinux/nuxt-auth-utils/commit/9d6b258))
- **release:** V0.0.14 ([1d0d0cc](https://github.com/atinux/nuxt-auth-utils/commit/1d0d0cc))
- Up deps ([a7bd06b](https://github.com/atinux/nuxt-auth-utils/commit/a7bd06b))
- **release:** V0.0.15 ([ec128cc](https://github.com/atinux/nuxt-auth-utils/commit/ec128cc))
- Better server types ([#51](https://github.com/atinux/nuxt-auth-utils/pull/51))
- Update deps ([b930118](https://github.com/atinux/nuxt-auth-utils/commit/b930118))
- **release:** V0.0.16 ([58268d7](https://github.com/atinux/nuxt-auth-utils/commit/58268d7))
- Update deps ([fdaa88c](https://github.com/atinux/nuxt-auth-utils/commit/fdaa88c))
- Add api test route ([9aed7fe](https://github.com/atinux/nuxt-auth-utils/commit/9aed7fe))
- Update deps in playground ([95c657f](https://github.com/atinux/nuxt-auth-utils/commit/95c657f))
- **release:** V0.0.17 ([a814b58](https://github.com/atinux/nuxt-auth-utils/commit/a814b58))
- **release:** V0.0.18 ([ea09e00](https://github.com/atinux/nuxt-auth-utils/commit/ea09e00))
- Fix types ([34dfb7b](https://github.com/atinux/nuxt-auth-utils/commit/34dfb7b))
- **release:** V0.0.19 ([a74c869](https://github.com/atinux/nuxt-auth-utils/commit/a74c869))
- **release:** V0.0.20 ([39ffaae](https://github.com/atinux/nuxt-auth-utils/commit/39ffaae))
- Update deps ([c8b8eb9](https://github.com/atinux/nuxt-auth-utils/commit/c8b8eb9))
- **release:** V0.0.21 ([f4b3512](https://github.com/atinux/nuxt-auth-utils/commit/f4b3512))
- **release:** V0.0.22 ([465e73e](https://github.com/atinux/nuxt-auth-utils/commit/465e73e))
- Migrate to eslint v9 ([964b67b](https://github.com/atinux/nuxt-auth-utils/commit/964b67b))
- Update deps ([a77a334](https://github.com/atinux/nuxt-auth-utils/commit/a77a334))
- Add vscode settings for eslint ([4f1afc9](https://github.com/atinux/nuxt-auth-utils/commit/4f1afc9))
- **release:** V0.0.23 ([b74d47b](https://github.com/atinux/nuxt-auth-utils/commit/b74d47b))
- Update deps ([3e42be4](https://github.com/atinux/nuxt-auth-utils/commit/3e42be4))
- **release:** V0.0.24 ([9063aeb](https://github.com/atinux/nuxt-auth-utils/commit/9063aeb))
- Update to latest `@nuxt/module-builder` ([c9e4ff7](https://github.com/atinux/nuxt-auth-utils/commit/c9e4ff7))
- **release:** V0.0.25 ([7fe6f84](https://github.com/atinux/nuxt-auth-utils/commit/7fe6f84))
- Add packageManager ([c323edc](https://github.com/atinux/nuxt-auth-utils/commit/c323edc))
- Add link to nuxt-authorization ([1b06908](https://github.com/atinux/nuxt-auth-utils/commit/1b06908))
- Update deps ([2fb5cff](https://github.com/atinux/nuxt-auth-utils/commit/2fb5cff))
- **release:** V0.1.0 ([6ea5685](https://github.com/atinux/nuxt-auth-utils/commit/6ea5685))
- **release:** V0.2.0 ([2d33c54](https://github.com/atinux/nuxt-auth-utils/commit/2d33c54))
- **release:** V0.2.1 ([4ba3289](https://github.com/atinux/nuxt-auth-utils/commit/4ba3289))
- **release:** V0.3.0 ([fd9df35](https://github.com/atinux/nuxt-auth-utils/commit/fd9df35))
- Update deps ([0132ea0](https://github.com/atinux/nuxt-auth-utils/commit/0132ea0))
- **release:** V0.3.1 ([633c004](https://github.com/atinux/nuxt-auth-utils/commit/633c004))
- **release:** V0.3.2 ([b4d5ce2](https://github.com/atinux/nuxt-auth-utils/commit/b4d5ce2))
- Typo in comment ([b96a017](https://github.com/atinux/nuxt-auth-utils/commit/b96a017))
- Update deps ([d8ab3f4](https://github.com/atinux/nuxt-auth-utils/commit/d8ab3f4))
- Lint fix ([a8928a3](https://github.com/atinux/nuxt-auth-utils/commit/a8928a3))
- **release:** V0.3.3 ([0345169](https://github.com/atinux/nuxt-auth-utils/commit/0345169))
- **release:** V0.3.4 ([07cf55e](https://github.com/atinux/nuxt-auth-utils/commit/07cf55e))
- Update .vscode ([6285ca2](https://github.com/atinux/nuxt-auth-utils/commit/6285ca2))
- Update @nuxt/module-builder ([ceaa47b](https://github.com/atinux/nuxt-auth-utils/commit/ceaa47b))
- Upadte X handler ([7e81c27](https://github.com/atinux/nuxt-auth-utils/commit/7e81c27))
- Fix X ([7269c61](https://github.com/atinux/nuxt-auth-utils/commit/7269c61))
- Lint fix ([cf75ab1](https://github.com/atinux/nuxt-auth-utils/commit/cf75ab1))
- Update deps ([35eff05](https://github.com/atinux/nuxt-auth-utils/commit/35eff05))
- **release:** V0.3.5 ([de0e01c](https://github.com/atinux/nuxt-auth-utils/commit/de0e01c))
- Update deps ([c4189b2](https://github.com/atinux/nuxt-auth-utils/commit/c4189b2))
- **release:** V0.3.6 ([6b5f5eb](https://github.com/atinux/nuxt-auth-utils/commit/6b5f5eb))
- Update deps ([50aba8d](https://github.com/atinux/nuxt-auth-utils/commit/50aba8d))
- **release:** V0.3.7 ([52d7e60](https://github.com/atinux/nuxt-auth-utils/commit/52d7e60))
- Add emailRequired for testing Gitlab ([408b580](https://github.com/atinux/nuxt-auth-utils/commit/408b580))
- Up ([bd37690](https://github.com/atinux/nuxt-auth-utils/commit/bd37690))
- **release:** V0.3.8 ([23ccd4c](https://github.com/atinux/nuxt-auth-utils/commit/23ccd4c))
- Update deps ([4a0e1e9](https://github.com/atinux/nuxt-auth-utils/commit/4a0e1e9))
- **release:** V0.3.9 ([3112481](https://github.com/atinux/nuxt-auth-utils/commit/3112481))
- Add state params in Google oauth ([f75e680](https://github.com/atinux/nuxt-auth-utils/commit/f75e680))
- Update deps ([5ae49ae](https://github.com/atinux/nuxt-auth-utils/commit/5ae49ae))
- **release:** V0.4.0 ([7da0c78](https://github.com/atinux/nuxt-auth-utils/commit/7da0c78))
- Remove unnecessary challenge cookie ([be2626b](https://github.com/atinux/nuxt-auth-utils/commit/be2626b))
- **release:** V0.4.1 ([9e7bd5a](https://github.com/atinux/nuxt-auth-utils/commit/9e7bd5a))
- **release:** V0.4.2 ([e039625](https://github.com/atinux/nuxt-auth-utils/commit/e039625))
- Update deps ([2719753](https://github.com/atinux/nuxt-auth-utils/commit/2719753))
- **release:** V0.4.3 ([c95cb73](https://github.com/atinux/nuxt-auth-utils/commit/c95cb73))
- **release:** V0.4.4 ([fce4e33](https://github.com/atinux/nuxt-auth-utils/commit/fce4e33))
- **playground:** Remove duplicate code ([edc14ce](https://github.com/atinux/nuxt-auth-utils/commit/edc14ce))
- ⚠️  Update simplewebauthn to v11 ([92e3e2e](https://github.com/atinux/nuxt-auth-utils/commit/92e3e2e))
- Update deps ([5a4ecb3](https://github.com/atinux/nuxt-auth-utils/commit/5a4ecb3))
- **release:** V0.5.0 ([404acc6](https://github.com/atinux/nuxt-auth-utils/commit/404acc6))
- Update deps ([8947e40](https://github.com/atinux/nuxt-auth-utils/commit/8947e40))
- **release:** V0.5.1 ([727b5b4](https://github.com/atinux/nuxt-auth-utils/commit/727b5b4))
- Fix package format ([247ec8f](https://github.com/atinux/nuxt-auth-utils/commit/247ec8f))
- **playground:** Max height for dropdow ([10951b0](https://github.com/atinux/nuxt-auth-utils/commit/10951b0))
- Update deps ([3e9422f](https://github.com/atinux/nuxt-auth-utils/commit/3e9422f))
- **playground:** Update deps ([1d0d7f7](https://github.com/atinux/nuxt-auth-utils/commit/1d0d7f7))
- Fix types ([a13b054](https://github.com/atinux/nuxt-auth-utils/commit/a13b054))
- **release:** V0.5.2 ([5434d1d](https://github.com/atinux/nuxt-auth-utils/commit/5434d1d))
- Update deps ([6072a74](https://github.com/atinux/nuxt-auth-utils/commit/6072a74))
- **release:** V0.5.3 ([9dc929c](https://github.com/atinux/nuxt-auth-utils/commit/9dc929c))
- Add SessionConfig type ([7633e27](https://github.com/atinux/nuxt-auth-utils/commit/7633e27))
- Fix types ([5d58645](https://github.com/atinux/nuxt-auth-utils/commit/5d58645))
- Update deps ([ffafb2c](https://github.com/atinux/nuxt-auth-utils/commit/ffafb2c))
- Rename jtw to jwt ([139197b](https://github.com/atinux/nuxt-auth-utils/commit/139197b))
- **release:** V0.5.4 ([21bff83](https://github.com/atinux/nuxt-auth-utils/commit/21bff83))
- Update packageManager to pnpm 9.13.2 ([fc0d991](https://github.com/atinux/nuxt-auth-utils/commit/fc0d991))
- **release:** V0.5.5 ([f2b4bbc](https://github.com/atinux/nuxt-auth-utils/commit/f2b4bbc))
- Update deps ([fb894bf](https://github.com/atinux/nuxt-auth-utils/commit/fb894bf))
- Update deps" ([f4ef630](https://github.com/atinux/nuxt-auth-utils/commit/f4ef630))
- **release:** V0.5.6 ([eef7119](https://github.com/atinux/nuxt-auth-utils/commit/eef7119))
- Lint fix ([3532d48](https://github.com/atinux/nuxt-auth-utils/commit/3532d48))
- Update deps ([f6f6b71](https://github.com/atinux/nuxt-auth-utils/commit/f6f6b71))
- Update deps ([7d09be5](https://github.com/atinux/nuxt-auth-utils/commit/7d09be5))
- Lint fix ([c9a3716](https://github.com/atinux/nuxt-auth-utils/commit/c9a3716))
- **release:** V0.5.7 ([4aedb34](https://github.com/atinux/nuxt-auth-utils/commit/4aedb34))
- Disable test:types ([ec9b727](https://github.com/atinux/nuxt-auth-utils/commit/ec9b727))
- Rename jtw to jwt ([#326](https://github.com/atinux/nuxt-auth-utils/pull/326))
- Update deps ([9cd39e8](https://github.com/atinux/nuxt-auth-utils/commit/9cd39e8))
- **release:** V0.5.8 ([44b06c6](https://github.com/atinux/nuxt-auth-utils/commit/44b06c6))
- **release:** V0.5.9 ([fff47f1](https://github.com/atinux/nuxt-auth-utils/commit/fff47f1))
- **release:** V0.5.10 ([42a2a7a](https://github.com/atinux/nuxt-auth-utils/commit/42a2a7a))
- **ci:** Fix corepack ([be2ccaf](https://github.com/atinux/nuxt-auth-utils/commit/be2ccaf))
- **release:** V0.5.11 ([1e99757](https://github.com/atinux/nuxt-auth-utils/commit/1e99757))
- Update deps ([1d4c52c](https://github.com/atinux/nuxt-auth-utils/commit/1d4c52c))
- **release:** V0.5.12 ([d47cac1](https://github.com/atinux/nuxt-auth-utils/commit/d47cac1))
- **playground:** Update nuxt version ([4852cd7](https://github.com/atinux/nuxt-auth-utils/commit/4852cd7))
- Fix types ([43d7d11](https://github.com/atinux/nuxt-auth-utils/commit/43d7d11))
- **release:** V0.5.13 ([ed221c1](https://github.com/atinux/nuxt-auth-utils/commit/ed221c1))
- **release:** V0.5.14 ([91a8ae1](https://github.com/atinux/nuxt-auth-utils/commit/91a8ae1))
- Align @simplewebauthn/types version ([#344](https://github.com/atinux/nuxt-auth-utils/pull/344))
- **release:** V0.5.15 ([6b61b88](https://github.com/atinux/nuxt-auth-utils/commit/6b61b88))
- **release:** V0.5.16 ([3a50df1](https://github.com/atinux/nuxt-auth-utils/commit/3a50df1))
- **release:** V0.5.17 ([34227d8](https://github.com/atinux/nuxt-auth-utils/commit/34227d8))
- **release:** V0.5.18 ([61dd7ba](https://github.com/atinux/nuxt-auth-utils/commit/61dd7ba))
- **release:** V0.5.19 ([acf94d9](https://github.com/atinux/nuxt-auth-utils/commit/acf94d9))
- Fix types ([#393](https://github.com/atinux/nuxt-auth-utils/pull/393))
- **release:** V0.5.20 ([f7127f5](https://github.com/atinux/nuxt-auth-utils/commit/f7127f5))

### 🎨 Styles

- Add lint script ([af884ff](https://github.com/atinux/nuxt-auth-utils/commit/af884ff))

### 🤖 CI

- Run lint + test actions in ci ([f50c1b5](https://github.com/atinux/nuxt-auth-utils/commit/f50c1b5))

#### ⚠️ Breaking Changes

- ⚠️  Support hybrid rendering ([#104](https://github.com/atinux/nuxt-auth-utils/pull/104))
- ⚠️  Call `fetch` hook if session is not empty instead of user defined ([#188](https://github.com/atinux/nuxt-auth-utils/pull/188))
- ⚠️  Rename `oauth<Provider>EventHandler` to`defineOAuth<Provider>EventHandler` ([#189](https://github.com/atinux/nuxt-auth-utils/pull/189))
- ⚠️  One export per provider for tree-shaking ([4f98b53](https://github.com/atinux/nuxt-auth-utils/commit/4f98b53))
- ⚠️  Update simplewebauthn to v11 ([92e3e2e](https://github.com/atinux/nuxt-auth-utils/commit/92e3e2e))

### ❤️ Contributors

- Josselinonduty ([@josselinonduty](http://github.com/josselinonduty))
- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Tejas  Gavankar ([@tejas161](http://github.com/tejas161))
- Artemis Mendrinos ([@mendrinos](http://github.com/mendrinos))
- Timothy Michael McMasters ([@Tmmcmasters](http://github.com/Tmmcmasters))
- Phof ([@phof](http://github.com/phof))
- Alain Hélaïli ([@helaili](http://github.com/helaili))
- Ahmed Rangel ([@ahmedrangel](http://github.com/ahmedrangel))
- Nathan Rowe ([@n-rowe](http://github.com/n-rowe))
- Dominik Opyd <dominik.opyd@gmail.com>
- Indrek Ardel <indrek@ardel.eu>
- Marios Antonoudiou ([@mariosant](http://github.com/mariosant))
- NiTrO0FuN ([@NiTrO0FuN](http://github.com/NiTrO0FuN))
- BeSaad ([@BeSaad](http://github.com/BeSaad))
- Alex ([@alexfriesen](http://github.com/alexfriesen))
- Mktcode <kontakt@markus-kottlaender.de>
- Neil Richter ([@noook](http://github.com/noook))
- H+ ([@justserdar](http://github.com/justserdar))
- Emmanuel Salomon ([@ManUtopiK](http://github.com/ManUtopiK))
- Alessandro Jean ([@alessandrojean](http://github.com/alessandrojean))
- David ([@GreenmeisterDavid](http://github.com/GreenmeisterDavid))
- Jonas ([@jonasfroeller](http://github.com/jonasfroeller))
- Devskillpro ([@devskillpro](http://github.com/devskillpro))
- Exit ([@exitss](http://github.com/exitss))
- Benjamin Stauß <benni@stauss.es>
- Thijs Wijnmaalen <thijs@wijnmaalen.name>
- Guilherme Guimarães <gui.cazaroto@gmail.com>
- Gage Keenan 
- Carl Gödecken ([@MasterCarl](http://github.com/MasterCarl))
- Sandro Circi ([@sandros94](http://github.com/sandros94))
- Justpeterpan <peter.busch@posteo.net>
- David Stranava 
- Brian Coleman ([@brianacdev](http://github.com/brianacdev))
- Aoor9 ([@aoor9](http://github.com/aoor9))
- Velka ([@Velka-DEV](http://github.com/Velka-DEV))
- Gerben Mulder <github.undergo381@passmail.net>
- Nekohaxx 
- FreeCoderX ([@yxw007](http://github.com/yxw007))
- Jules Libert <jules.lib@gmail.com>
- Mathieu NICOLAS 
- Julian Renard <renard.julian@gmail.com>
- Estéban <e.soubiran25@gmail.com>
- Yizack Rangel <yizackr@gmail.com>
- Israel Ortuño <ai.ortuno@gmail.com>
- Daniel Roe ([@danielroe](http://github.com/danielroe))
- Alex Blumgart <dev.blumgart@yandex.ru>
- Rudo Kemper ([@rudokemper](http://github.com/rudokemper))
- Ivailo Panamski <ipanamski@gmail.com>
- Zack Spear 
- Alexander <me@hywax.space>
- Kevin Olson <acidjazz@gmail.com>
- TcarterBAMF ([@tcarterBAMF](http://github.com/tcarterBAMF))
- Fayaz Ahmed <fayazara@gmail.com>
- Jan Fröhlich <jan.froehlich.janf@gmail.com>
- Stonegate 
- Yue JIN 
- Paulo Queiroz 
- Timi Omoyeni <omoyenitimi@gmail.com>
- Ozan Cakir 
- Adam Hudák 
- Deth <gabriel@rosa.dev.br>
- Conrawl Rogers <diizzayy@gmail.com>
- Max <maximogarciamtnez@gmail.com>
- André Agro Ferreira 
- Maximilian Götz-Mikus <hi@kask.at>
- Harlan Wilton <harlan@harlanzw.com>
- Dvir Hazout <dvir@dazz.io>
- Silvio Eckl <silvio@whitespace.no>
- José Manuel Madriaza Caravia 
- Jakub Frelik <j.frelik.it@outlook.com>
- Uģis <berzinsu@gmail.com>
- Sigve Hansen <sighan12@gmail.com>
- Arash 
- Samuel LEFEVRE 
- Antoine Lassier <toinousp@gmail.com>
- Akshara Hegde <akshara.dt@gmail.com>

## v0.5.20

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.19...v0.5.20)

### 📖 Documentation

- Update readme file to fix path to OAuth provider ([9d816a8](https://github.com/atinux/nuxt-auth-utils/commit/9d816a8))

### 🏡 Chore

- Fix types ([#393](https://github.com/atinux/nuxt-auth-utils/pull/393))

### ❤️ Contributors

- Tejas  Gavankar ([@tejas161](http://github.com/tejas161))
- Sébastien Chopin <seb@nuxt.com>

## v0.5.19

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.18...v0.5.19)

### 🚀 Enhancements

- Add support for authorization parameters and ensure state param is included from query when present in Facebook & Microsoft OAuth ([#386](https://github.com/atinux/nuxt-auth-utils/pull/386))

### 🩹 Fixes

- Explicit Return Type on getUserSession ([#379](https://github.com/atinux/nuxt-auth-utils/pull/379))

### ❤️ Contributors

- Artemis Mendrinos ([@mendrinos](http://github.com/mendrinos))
- Timothy Michael McMasters ([@Tmmcmasters](http://github.com/Tmmcmasters))

## v0.5.18

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.17...v0.5.18)

### 🚀 Enhancements

- Support GitHub Enterprise Server and GHE.com ([#383](https://github.com/atinux/nuxt-auth-utils/pull/383))
- Add Salesforce, Slack and Heroku OAuth providers ([#382](https://github.com/atinux/nuxt-auth-utils/pull/382))

### ❤️ Contributors

- Phof ([@phof](http://github.com/phof))
- Alain Hélaïli ([@helaili](http://github.com/helaili))

## v0.5.17

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.16...v0.5.17)

### 🚀 Enhancements

- Add LiveChat OAuth ([#376](https://github.com/atinux/nuxt-auth-utils/pull/376))
- Add azure b2c oauth provider ([#362](https://github.com/atinux/nuxt-auth-utils/pull/362))
- Add kick provider ([#360](https://github.com/atinux/nuxt-auth-utils/pull/360))

### 🩹 Fixes

- Verify steam credentials ([#365](https://github.com/atinux/nuxt-auth-utils/pull/365))
- Remove `ohash` dependency ([#377](https://github.com/atinux/nuxt-auth-utils/pull/377))
- **oauth, apple:** Return tokens in response ([#373](https://github.com/atinux/nuxt-auth-utils/pull/373))
- **oauth, facebook:** Prevent duplication of config.fields and config.scope in defu merge ([#375](https://github.com/atinux/nuxt-auth-utils/pull/375))

### ❤️ Contributors

- Ahmed Rangel ([@ahmedrangel](http://github.com/ahmedrangel))
- Nathan Rowe ([@n-rowe](http://github.com/n-rowe))
- Artemis Mendrinos ([@mendrinos](http://github.com/mendrinos))
- Dominik Opyd <dominik.opyd@gmail.com>
- Indrek Ardel <indrek@ardel.eu>
- Marios Antonoudiou ([@mariosant](http://github.com/mariosant))
- NiTrO0FuN ([@NiTrO0FuN](http://github.com/NiTrO0FuN))

## v0.5.16

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.15...v0.5.16)

### 🚀 Enhancements

- Custom params for Keycloak ([#355](https://github.com/atinux/nuxt-auth-utils/pull/355))

### ❤️ Contributors

- BeSaad ([@BeSaad](http://github.com/BeSaad))

## v0.5.15

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.14...v0.5.15)

### 🩹 Fixes

- Import useError ([b7e078d](https://github.com/atinux/nuxt-auth-utils/commit/b7e078d))

### 📖 Documentation

- Wrong var name in README.md ([#345](https://github.com/atinux/nuxt-auth-utils/pull/345))

### 🏡 Chore

- Align @simplewebauthn/types version ([#344](https://github.com/atinux/nuxt-auth-utils/pull/344))

### ❤️ Contributors

- Sébastien Chopin <atinux@gmail.com>
- Alex ([@alexfriesen](http://github.com/alexfriesen))
- Mktcode <kontakt@markus-kottlaender.de>

## v0.5.14

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.13...v0.5.14)

### 🩹 Fixes

- Move atproto util in runtime ([ff2ddc9](https://github.com/atinux/nuxt-auth-utils/commit/ff2ddc9))

### ❤️ Contributors

- Sébastien Chopin <atinux@gmail.com>

## v0.5.13

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.12...v0.5.13)

### 🩹 Fixes

- **bluesky:** Use local map for session storing ([#340](https://github.com/atinux/nuxt-auth-utils/pull/340))

### 🏡 Chore

- **playground:** Update nuxt version ([4852cd7](https://github.com/atinux/nuxt-auth-utils/commit/4852cd7))
- Fix types ([43d7d11](https://github.com/atinux/nuxt-auth-utils/commit/43d7d11))

### ❤️ Contributors

- Neil Richter ([@noook](http://github.com/noook))
- Sébastien Chopin <atinux@gmail.com>

## v0.5.12

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.11...v0.5.12)

### 🚀 Enhancements

- **session:** Add generated session id ([#338](https://github.com/atinux/nuxt-auth-utils/pull/338))
- Add bluesky as a provider ([#281](https://github.com/atinux/nuxt-auth-utils/pull/281))

### 🏡 Chore

- Update deps ([1d4c52c](https://github.com/atinux/nuxt-auth-utils/commit/1d4c52c))

### ❤️ Contributors

- Sébastien Chopin <atinux@gmail.com>
- Neil Richter <me@neilrichter.com>

## v0.5.11

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.10...v0.5.11)

### 🚀 Enhancements

- Set `email_verified` in `user` on GitHub provider ([#332](https://github.com/atinux/nuxt-auth-utils/pull/332))
- **composable:** Add `openInPopup(route, { width, height })` ([#336](https://github.com/atinux/nuxt-auth-utils/pull/336))
- Add Gitea Oauth Provider ([#335](https://github.com/atinux/nuxt-auth-utils/pull/335))

### 🩹 Fixes

- Dammit corepack ([239f97a](https://github.com/atinux/nuxt-auth-utils/commit/239f97a))
- **microsoft:** Fix duplicated scopes ([#331](https://github.com/atinux/nuxt-auth-utils/pull/331))

### 🏡 Chore

- **release:** V0.5.10 ([42a2a7a](https://github.com/atinux/nuxt-auth-utils/commit/42a2a7a))
- **ci:** Fix corepack ([be2ccaf](https://github.com/atinux/nuxt-auth-utils/commit/be2ccaf))

### ❤️ Contributors

- H+ ([@justserdar](http://github.com/justserdar))
- Emmanuel Salomon ([@ManUtopiK](http://github.com/ManUtopiK))
- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Alessandro Jean ([@alessandrojean](http://github.com/alessandrojean))

## v0.5.10

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.9...v0.5.10)

### 🚀 Enhancements

- Add apple provider ([#328](https://github.com/atinux/nuxt-auth-utils/pull/328))

### 📖 Documentation

- Typo ([8b132e4](https://github.com/atinux/nuxt-auth-utils/commit/8b132e4))
- Improve example ([9d191a1](https://github.com/atinux/nuxt-auth-utils/commit/9d191a1))

### ❤️ Contributors

- David ([@GreenmeisterDavid](http://github.com/GreenmeisterDavid))
- Sébastien Chopin ([@atinux](http://github.com/atinux))

## v0.5.9

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.8...v0.5.9)

### 🚀 Enhancements

- Add support for websocket handler ([#327](https://github.com/atinux/nuxt-auth-utils/pull/327))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))

## v0.5.8

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.7...v0.5.8)

### 🚀 Enhancements

- Self-hosted Gitlab instances ([#323](https://github.com/atinux/nuxt-auth-utils/pull/323))
- Add Line OAuth provider ([#312](https://github.com/atinux/nuxt-auth-utils/pull/312))
- Add atlassian oauth-provider ([#307](https://github.com/atinux/nuxt-auth-utils/pull/307), [#308](https://github.com/atinux/nuxt-auth-utils/pull/308))

### 🩹 Fixes

- Add discord oauth error ([#316](https://github.com/atinux/nuxt-auth-utils/pull/316))
- Normalise errors when user not accessible ([c98ea5d](https://github.com/atinux/nuxt-auth-utils/commit/c98ea5d))

### 🏡 Chore

- Disable test:types ([ec9b727](https://github.com/atinux/nuxt-auth-utils/commit/ec9b727))
- Rename jtw to jwt ([#326](https://github.com/atinux/nuxt-auth-utils/pull/326))
- Update deps ([9cd39e8](https://github.com/atinux/nuxt-auth-utils/commit/9cd39e8))

### ❤️ Contributors

- Sébastien Chopin <atinux@gmail.com>
- Jonas ([@jonasfroeller](http://github.com/jonasfroeller))
- Devskillpro ([@devskillpro](http://github.com/devskillpro))
- Exit ([@exitss](http://github.com/exitss))
- Benjamin Stauß <benni@stauss.es>
- Thijs Wijnmaalen <thijs@wijnmaalen.name>

## v0.5.7

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.6...v0.5.7)

### 🚀 Enhancements

- Keycloak internal server URL ([ac61ae5](https://github.com/atinux/nuxt-auth-utils/commit/ac61ae5))
- **cognito:** Integrate OpenID Connect discovery for improved OAuth flow ([7a01cc3](https://github.com/atinux/nuxt-auth-utils/commit/7a01cc3))
- Add hubspot provider ([1a79baf](https://github.com/atinux/nuxt-auth-utils/commit/1a79baf))

### 🩹 Fixes

- Make sure the required env is checked ([#306](https://github.com/atinux/nuxt-auth-utils/pull/306))

### 🏡 Chore

- Lint fix ([3532d48](https://github.com/atinux/nuxt-auth-utils/commit/3532d48))
- Update deps ([f6f6b71](https://github.com/atinux/nuxt-auth-utils/commit/f6f6b71))
- Update deps ([7d09be5](https://github.com/atinux/nuxt-auth-utils/commit/7d09be5))
- Lint fix ([c9a3716](https://github.com/atinux/nuxt-auth-utils/commit/c9a3716))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Guilherme Guimarães <gui.cazaroto@gmail.com>
- Gage Keenan ([@kilakewe](http://github.com/kilakewe))
- Carl Gödecken ([@MasterCarl](http://github.com/MasterCarl))

## v0.5.6

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.5...v0.5.6)

### 🚀 Enhancements

- Adding `organization_id` option for WorkOS provider ([677b226](https://github.com/atinux/nuxt-auth-utils/commit/677b226))
- Add strava oauth provider ([96363b2](https://github.com/atinux/nuxt-auth-utils/commit/96363b2))

### 🩹 Fixes

- Seznam config ([90d0d18](https://github.com/atinux/nuxt-auth-utils/commit/90d0d18))
- **instagram:** Oauth provider ([192e0e7](https://github.com/atinux/nuxt-auth-utils/commit/192e0e7))

### 🏡 Chore

- Update deps ([fb894bf](https://github.com/atinux/nuxt-auth-utils/commit/fb894bf))
- Update deps" ([f4ef630](https://github.com/atinux/nuxt-auth-utils/commit/f4ef630))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Sandro Circi ([@sandros94](http://github.com/sandros94))
- Justpeterpan <peter.busch@posteo.net>
- David Stranava ([@stranavad](http://github.com/stranavad))
- Brian Coleman ([@brianacdev](http://github.com/brianacdev))

## v0.5.5

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.4...v0.5.5)

### 🚀 Enhancements

- Add workos oauth provider ([bfa2a88](https://github.com/atinux/nuxt-auth-utils/commit/bfa2a88))
- Add seznam oauth provider ([#285](https://github.com/atinux/nuxt-auth-utils/pull/285))
- **webauthn:** Add event to validateUser to track authenticated users ([#287](https://github.com/atinux/nuxt-auth-utils/pull/287))

### 🏡 Chore

- Update packageManager to pnpm 9.13.2 ([fc0d991](https://github.com/atinux/nuxt-auth-utils/commit/fc0d991))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- David Stranava ([@stranavad](http://github.com/stranavad))
- Brian Coleman <me@briancoleman.net>

## v0.5.4

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.3...v0.5.4)

### 🚀 Enhancements

- Forward set-cookie header for `useUserSession().clear()` ([#282](https://github.com/atinux/nuxt-auth-utils/pull/282))

### 🏡 Chore

- Add SessionConfig type ([7633e27](https://github.com/atinux/nuxt-auth-utils/commit/7633e27))
- Fix types ([5d58645](https://github.com/atinux/nuxt-auth-utils/commit/5d58645))
- Update deps ([ffafb2c](https://github.com/atinux/nuxt-auth-utils/commit/ffafb2c))
- Rename jtw to jwt ([139197b](https://github.com/atinux/nuxt-auth-utils/commit/139197b))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))

## v0.5.3

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.2...v0.5.3)

### 🚀 Enhancements

- Add authentik provider ([33686af](https://github.com/atinux/nuxt-auth-utils/commit/33686af))

### 🩹 Fixes

- **composable:** Use same context for `clear` and `fetch` ([#278](https://github.com/atinux/nuxt-auth-utils/pull/278))

### 🏡 Chore

- Update deps ([6072a74](https://github.com/atinux/nuxt-auth-utils/commit/6072a74))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Aoor9 ([@aoor9](http://github.com/aoor9))

## v0.5.2

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.1...v0.5.2)

### 🚀 Enhancements

- Zitadel provider implementation ([d4c0b5a](https://github.com/atinux/nuxt-auth-utils/commit/d4c0b5a))

### 🏡 Chore

- **release:** V0.5.1 ([727b5b4](https://github.com/atinux/nuxt-auth-utils/commit/727b5b4))
- Fix package format ([247ec8f](https://github.com/atinux/nuxt-auth-utils/commit/247ec8f))
- **playground:** Max height for dropdow ([10951b0](https://github.com/atinux/nuxt-auth-utils/commit/10951b0))
- Update deps ([3e9422f](https://github.com/atinux/nuxt-auth-utils/commit/3e9422f))
- **playground:** Update deps ([1d0d7f7](https://github.com/atinux/nuxt-auth-utils/commit/1d0d7f7))
- Fix types ([a13b054](https://github.com/atinux/nuxt-auth-utils/commit/a13b054))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Velka ([@Velka-DEV](http://github.com/Velka-DEV))

## v0.5.1

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.5.0...v0.5.1)

### 🩹 Fixes

- `useWebAuthn` composable registration & fix `allowCredentials` / `excludeCredentials` option ([#266](https://github.com/atinux/nuxt-auth-utils/pull/266))

### 🏡 Chore

- **release:** V0.5.0 ([404acc6](https://github.com/atinux/nuxt-auth-utils/commit/404acc6))
- Update deps ([8947e40](https://github.com/atinux/nuxt-auth-utils/commit/8947e40))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Gerben Mulder <github.undergo381@passmail.net>

## v0.5.0

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.4.4...v0.5.0)

### 📖 Documentation

- Set webauthn version to v10 ([ca151c7](https://github.com/atinux/nuxt-auth-utils/commit/ca151c7))
- Fix typo ([#251](https://github.com/atinux/nuxt-auth-utils/pull/251))

### 🏡 Chore

- **playground:** Remove duplicate code ([edc14ce](https://github.com/atinux/nuxt-auth-utils/commit/edc14ce))
- ⚠️  Update simplewebauthn to v11 ([92e3e2e](https://github.com/atinux/nuxt-auth-utils/commit/92e3e2e))
- Update deps ([5a4ecb3](https://github.com/atinux/nuxt-auth-utils/commit/5a4ecb3))

#### ⚠️ Breaking Changes

- ⚠️  Update simplewebauthn to v11 ([92e3e2e](https://github.com/atinux/nuxt-auth-utils/commit/92e3e2e))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Gerben Mulder <github.undergo381@passmail.net>
- Nekohaxx ([@nekohaxx](http://github.com/nekohaxx))
- FreeCoderX ([@yxw007](http://github.com/yxw007))

## v0.4.4

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.4.3...v0.4.4)

### 🩹 Fixes

- Fetch hook is called even is user is not set ([#209](https://github.com/atinux/nuxt-auth-utils/pull/209))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))

## v0.4.3

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.4.2...v0.4.3)

### 🚀 Enhancements

- ClearUserSession takes config arg as well ([69eaf42](https://github.com/atinux/nuxt-auth-utils/commit/69eaf42))
- Add linear provider ([c1291cd](https://github.com/atinux/nuxt-auth-utils/commit/c1291cd))

### 🏡 Chore

- Update deps ([2719753](https://github.com/atinux/nuxt-auth-utils/commit/2719753))

### ❤️ Contributors

- Jules Libert <jules.lib@gmail.com>
- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Mathieu NICOLAS ([@mathieunicolas](http://github.com/mathieunicolas))

## v0.4.2

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.4.1...v0.4.2)

### 🚀 Enhancements

- Add polar provider ([2682bcb](https://github.com/atinux/nuxt-auth-utils/commit/2682bcb))

### 📖 Documentation

- Improvement ([3bd76b0](https://github.com/atinux/nuxt-auth-utils/commit/3bd76b0))

### ❤️ Contributors

- Ahmed Rangel ([@ahmedrangel](http://github.com/ahmedrangel))
- Sébastien Chopin ([@atinux](http://github.com/atinux))

## v0.4.1

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.4.0...v0.4.1)

### 📖 Documentation

- Typo ([c16d014](https://github.com/atinux/nuxt-auth-utils/commit/c16d014))
- Update links ([2ed5e17](https://github.com/atinux/nuxt-auth-utils/commit/2ed5e17))

### 🏡 Chore

- Remove unnecessary challenge cookie ([be2626b](https://github.com/atinux/nuxt-auth-utils/commit/be2626b))

### ❤️ Contributors

- Gerben Mulder <github.undergo381@passmail.net>
- Sébastien Chopin ([@atinux](http://github.com/atinux))

## v0.4.0

[compare changes](https://github.com/atinux/nuxt-auth-utils/compare/v0.3.9...v0.4.0)

### 🚀 Enhancements

- Add Dropbox as supported oauth provider ([#183](https://github.com/atinux/nuxt-auth-utils/pull/183))
- ⚠️  Call `fetch` hook if session is not empty instead of user defined ([#188](https://github.com/atinux/nuxt-auth-utils/pull/188))
- ⚠️  Rename `oauth<Provider>EventHandler` to`defineOAuth<Provider>EventHandler` ([#189](https://github.com/atinux/nuxt-auth-utils/pull/189))
- Add `hashPassword` & `verifyPassword` server utils ([0c4d050](https://github.com/atinux/nuxt-auth-utils/commit/0c4d050))
- Webauthn (passkey) support ([a90b173](https://github.com/atinux/nuxt-auth-utils/commit/a90b173))

### 🩹 Fixes

- **steam:** Improve open id validation ([#184](https://github.com/atinux/nuxt-auth-utils/pull/184))

### 🏡 Chore

- Add state params in Google oauth ([f75e680](https://github.com/atinux/nuxt-auth-utils/commit/f75e680))
- Update deps ([5ae49ae](https://github.com/atinux/nuxt-auth-utils/commit/5ae49ae))

#### ⚠️ Breaking Changes

- ⚠️  Call `fetch` hook if session is not empty instead of user defined ([#188](https://github.com/atinux/nuxt-auth-utils/pull/188))
- ⚠️  Rename `oauth<Provider>EventHandler` to`defineOAuth<Provider>EventHandler` ([#189](https://github.com/atinux/nuxt-auth-utils/pull/189))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Gerben Mulder <github.undergo381@passmail.net>
- Julian Renard <renard.julian@gmail.com>
- Estéban <e.soubiran25@gmail.com>
- Ahmed Rangel ([@ahmedrangel](http://github.com/ahmedrangel))
- Yizack Rangel ([@Yizack](http://github.com/Yizack))

## v0.3.9

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.3.8...v0.3.9)

### 🩹 Fixes

- UserSession secure type augmentation ([#181](https://github.com/Atinux/nuxt-auth-utils/pull/181))

### 🏡 Chore

- Update deps ([4a0e1e9](https://github.com/Atinux/nuxt-auth-utils/commit/4a0e1e9))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Israel Ortuño <ai.ortuno@gmail.com>

## v0.3.8

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.3.7...v0.3.8)

### 🚀 Enhancements

- Add Gitlab provider ([fec746f](https://github.com/Atinux/nuxt-auth-utils/commit/fec746f))
- Add instagram provider ([3bd553c](https://github.com/Atinux/nuxt-auth-utils/commit/3bd553c))
- Add vk provider ([6581f12](https://github.com/Atinux/nuxt-auth-utils/commit/6581f12))
- Add support for private data & config argument ([#171](https://github.com/Atinux/nuxt-auth-utils/pull/171))

### 🩹 Fixes

- Ensure plugin declaration files are emitted ([#170](https://github.com/Atinux/nuxt-auth-utils/pull/170))

### 📖 Documentation

- Add note about cookie size ([a725436](https://github.com/Atinux/nuxt-auth-utils/commit/a725436))
- Add note to readme about session API route ([ddf38c1](https://github.com/Atinux/nuxt-auth-utils/commit/ddf38c1))

### 🏡 Chore

- Add emailRequired for testing Gitlab ([408b580](https://github.com/Atinux/nuxt-auth-utils/commit/408b580))
- Up ([bd37690](https://github.com/Atinux/nuxt-auth-utils/commit/bd37690))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Daniel Roe ([@danielroe](http://github.com/danielroe))
- Alex Blumgart <dev.blumgart@yandex.ru>
- Sandro Circi ([@sandros94](http://github.com/sandros94))
- Rudo Kemper ([@rudokemper](http://github.com/rudokemper))

## v0.3.7

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.3.6...v0.3.7)

### 🩹 Fixes

- Paypal tokens request requires encoded `redirect_uri` ([8bf3b0b](https://github.com/Atinux/nuxt-auth-utils/commit/8bf3b0b))

### 🏡 Chore

- Update deps ([50aba8d](https://github.com/Atinux/nuxt-auth-utils/commit/50aba8d))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Yizack Rangel ([@Yizack](http://github.com/Yizack))

## v0.3.6

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.3.5...v0.3.6)

### 🚀 Enhancements

- Add tiktok provider ([c1b1f44](https://github.com/Atinux/nuxt-auth-utils/commit/c1b1f44))

### 💅 Refactors

- Request token ([925f688](https://github.com/Atinux/nuxt-auth-utils/commit/925f688))

### 📖 Documentation

- Fix typo ([8d3af7e](https://github.com/Atinux/nuxt-auth-utils/commit/8d3af7e))

### 🏡 Chore

- Update deps ([c4189b2](https://github.com/Atinux/nuxt-auth-utils/commit/c4189b2))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Ahmed Rangel ([@ahmedrangel](http://github.com/ahmedrangel))
- Estéban <e.soubiran25@gmail.com>
- Ivailo Panamski <ipanamski@gmail.com>

## v0.3.5

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.3.4...v0.3.5)

### 🚀 Enhancements

- Cognito oauth support custom domain ([4ad11a4](https://github.com/Atinux/nuxt-auth-utils/commit/4ad11a4))

### 🩹 Fixes

- Fetch session directly when ssr disabled ([#151](https://github.com/Atinux/nuxt-auth-utils/pull/151))

### 💅 Refactors

- Handle missing configuration error ([5675aaf](https://github.com/Atinux/nuxt-auth-utils/commit/5675aaf))
- Handle access token error response ([a1b3fbb](https://github.com/Atinux/nuxt-auth-utils/commit/a1b3fbb))

### 🏡 Chore

- Update .vscode ([6285ca2](https://github.com/Atinux/nuxt-auth-utils/commit/6285ca2))
- Update @nuxt/module-builder ([ceaa47b](https://github.com/Atinux/nuxt-auth-utils/commit/ceaa47b))
- Upadte X handler ([7e81c27](https://github.com/Atinux/nuxt-auth-utils/commit/7e81c27))
- Fix X ([7269c61](https://github.com/Atinux/nuxt-auth-utils/commit/7269c61))
- Lint fix ([cf75ab1](https://github.com/Atinux/nuxt-auth-utils/commit/cf75ab1))
- Update deps ([35eff05](https://github.com/Atinux/nuxt-auth-utils/commit/35eff05))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Estéban <e.soubiran25@gmail.com>
- Zack Spear ([@zackspear](http://github.com/zackspear))
- Alexander ([@hywax](http://github.com/hywax))

## v0.3.4

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.3.3...v0.3.4)

### 🚀 Enhancements

- Support redirectURL config for all providers ([cdca787](https://github.com/Atinux/nuxt-auth-utils/commit/cdca787))

### ❤️ Contributors

- Kevin Olson ([@acidjazz](http://github.com/acidjazz))

## v0.3.3

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.3.2...v0.3.3)

### 🚀 Enhancements

- Support `NUXT_OAUTH_MICROSOFT_REDIRECT_URL` ([9979f0d](https://github.com/Atinux/nuxt-auth-utils/commit/9979f0d))
- Add support nitro prefix env ([58ebf85](https://github.com/Atinux/nuxt-auth-utils/commit/58ebf85))

### 📖 Documentation

- Update nitro version ([848cebe](https://github.com/Atinux/nuxt-auth-utils/commit/848cebe))

### 🏡 Chore

- Typo in comment ([b96a017](https://github.com/Atinux/nuxt-auth-utils/commit/b96a017))
- Update deps ([d8ab3f4](https://github.com/Atinux/nuxt-auth-utils/commit/d8ab3f4))
- Lint fix ([a8928a3](https://github.com/Atinux/nuxt-auth-utils/commit/a8928a3))

### ❤️ Contributors

- Sébastien Chopin ([@atinux](http://github.com/atinux))
- Alexander <a.hywax@gmail.com>
- TcarterBAMF ([@tcarterBAMF](http://github.com/tcarterBAMF))

## v0.3.2

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.3.1...v0.3.2)

### 🩹 Fixes

- Add missing session in AuthState ([3e39727](https://github.com/Atinux/nuxt-auth-utils/commit/3e39727))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.3.1

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.3.0...v0.3.1)

### 🩹 Fixes

- Always return 200 for session endpoint ([#130](https://github.com/Atinux/nuxt-auth-utils/pull/130))

### 📖 Documentation

- Fix event handler name in example ([a4cfa89](https://github.com/Atinux/nuxt-auth-utils/commit/a4cfa89))

### 🏡 Chore

- Update deps ([0132ea0](https://github.com/Atinux/nuxt-auth-utils/commit/0132ea0))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Estéban ([@Barbapapazes](http://github.com/Barbapapazes))

## v0.3.0

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.2.1...v0.3.0)

### 🔥 Performance

- ⚠️  One export per provider for tree-shaking ([4f98b53](https://github.com/Atinux/nuxt-auth-utils/commit/4f98b53))

### 📖 Documentation

- Add TS signature ([04a5d88](https://github.com/Atinux/nuxt-auth-utils/commit/04a5d88))
- Add note about dependencies ([67b5542](https://github.com/Atinux/nuxt-auth-utils/commit/67b5542))

#### ⚠️ Breaking Changes

- ⚠️  One export per provider for tree-shaking ([4f98b53](https://github.com/Atinux/nuxt-auth-utils/commit/4f98b53))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Estéban ([@Barbapapazes](http://github.com/Barbapapazes))

## v0.2.1

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.2.0...v0.2.1)

### 🚀 Enhancements

- X/Twitter email requirement enhancement ([65d6324](https://github.com/Atinux/nuxt-auth-utils/commit/65d6324))
- Add yandex oauth ([22bd974](https://github.com/Atinux/nuxt-auth-utils/commit/22bd974))

### 🎨 Styles

- Add lint script ([af884ff](https://github.com/Atinux/nuxt-auth-utils/commit/af884ff))

### ❤️ Contributors

- Alex <dev.blumgart@yandex.ru>
- Estéban ([@Barbapapazes](http://github.com/Barbapapazes))
- Fayaz Ahmed ([@fayazara](http://github.com/fayazara))

## v0.2.0

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.25...v0.2.0)

### 🚀 Enhancements

- ⚠️  Support hybrid rendering ([#104](https://github.com/Atinux/nuxt-auth-utils/pull/104))
- Add steam as supported oauth provider ([c8b02d0](https://github.com/Atinux/nuxt-auth-utils/commit/c8b02d0))
- Add paypal as supported oauth provider ([57ea01e](https://github.com/Atinux/nuxt-auth-utils/commit/57ea01e))
- Add x(formerly twitter) as supported oauth provider ([a0be1f2](https://github.com/Atinux/nuxt-auth-utils/commit/a0be1f2))
- Add xsuaa provider ([9afb9eb](https://github.com/Atinux/nuxt-auth-utils/commit/9afb9eb))

### 💅 Refactors

- Replace ofetch with $fetch ([a7df1b5](https://github.com/Atinux/nuxt-auth-utils/commit/a7df1b5))

### 📖 Documentation

- Fix typos ([149448a](https://github.com/Atinux/nuxt-auth-utils/commit/149448a))
- Include SSR instructions in the README, fixes #97 ([#99](https://github.com/Atinux/nuxt-auth-utils/pull/99), [#97](https://github.com/Atinux/nuxt-auth-utils/issues/97))
- Update readme ([7a4dcfb](https://github.com/Atinux/nuxt-auth-utils/commit/7a4dcfb))
- Add X in readme ([b452d60](https://github.com/Atinux/nuxt-auth-utils/commit/b452d60))

### 🏡 Chore

- Add packageManager ([c323edc](https://github.com/Atinux/nuxt-auth-utils/commit/c323edc))
- Add link to nuxt-authorization ([1b06908](https://github.com/Atinux/nuxt-auth-utils/commit/1b06908))
- Update deps ([2fb5cff](https://github.com/Atinux/nuxt-auth-utils/commit/2fb5cff))
- **release:** V0.1.0 ([6ea5685](https://github.com/Atinux/nuxt-auth-utils/commit/6ea5685))

#### ⚠️ Breaking Changes

- ⚠️  Support hybrid rendering ([#104](https://github.com/Atinux/nuxt-auth-utils/pull/104))

### ❤️ Contributors

- Jan Fröhlich ([@zanfee](http://github.com/zanfee))
- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Stonegate 
- Yizack Rangel ([@Yizack](http://github.com/Yizack))
- Ahmed Rangel ([@ahmedrangel](http://github.com/ahmedrangel))
- Yue JIN ([@kingyue737](http://github.com/kingyue737))
- Paulo Queiroz ([@raggesilver](http://github.com/raggesilver))
- Timi Omoyeni ([@Timibadass](http://github.com/Timibadass))

## v0.1.0

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.25...v0.1.0)

### 🚀 Enhancements

- ⚠️  Support hybrid rendering ([#104](https://github.com/Atinux/nuxt-auth-utils/pull/104))

### 📖 Documentation

- Fix typos ([149448a](https://github.com/Atinux/nuxt-auth-utils/commit/149448a))
- Include SSR instructions in the README, fixes #97 ([#99](https://github.com/Atinux/nuxt-auth-utils/pull/99), [#97](https://github.com/Atinux/nuxt-auth-utils/issues/97))

### 🏡 Chore

- Add packageManager ([c323edc](https://github.com/Atinux/nuxt-auth-utils/commit/c323edc))
- Add link to nuxt-authorization ([1b06908](https://github.com/Atinux/nuxt-auth-utils/commit/1b06908))
- Update deps ([2fb5cff](https://github.com/Atinux/nuxt-auth-utils/commit/2fb5cff))

#### ⚠️ Breaking Changes

- ⚠️  Support hybrid rendering ([#104](https://github.com/Atinux/nuxt-auth-utils/pull/104))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Paulo Queiroz ([@raggesilver](http://github.com/raggesilver))
- Timi Omoyeni ([@Timibadass](http://github.com/Timibadass))

## v0.0.25

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.24...v0.0.25)

### 🚀 Enhancements

- Add fields support to facebook provider ([8e53936](https://github.com/Atinux/nuxt-auth-utils/commit/8e53936))

### 🏡 Chore

- Update to latest `@nuxt/module-builder` ([c9e4ff7](https://github.com/Atinux/nuxt-auth-utils/commit/c9e4ff7))

### ❤️ Contributors

- Ozan Cakir ([@ozancakir](http://github.com/ozancakir))
- Daniel Roe ([@danielroe](http://github.com/danielroe))

## v0.0.24

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.23...v0.0.24)

### 🚀 Enhancements

- Add facebook OAuth provider ([777d8b2](https://github.com/Atinux/nuxt-auth-utils/commit/777d8b2))

### 🏡 Chore

- Update deps ([3e42be4](https://github.com/Atinux/nuxt-auth-utils/commit/3e42be4))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Adam Hudák ([@adam-hudak](http://github.com/adam-hudak))

## v0.0.23

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.22...v0.0.23)

### 🚀 Enhancements

- Add opts to requireUserSession for error message and status code customization ([015e847](https://github.com/Atinux/nuxt-auth-utils/commit/015e847))

### 🩹 Fixes

- Avoid duplicate trigger of session fetch hook due to request retry ([5fac9a1](https://github.com/Atinux/nuxt-auth-utils/commit/5fac9a1))

### 📖 Documentation

- Removed reference to /api in readme ([#77](https://github.com/Atinux/nuxt-auth-utils/pull/77))

### 🏡 Chore

- Migrate to eslint v9 ([964b67b](https://github.com/Atinux/nuxt-auth-utils/commit/964b67b))
- Update deps ([a77a334](https://github.com/Atinux/nuxt-auth-utils/commit/a77a334))
- Add vscode settings for eslint ([4f1afc9](https://github.com/Atinux/nuxt-auth-utils/commit/4f1afc9))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Deth <gabriel@rosa.dev.br>
- Conrawl Rogers <diizzayy@gmail.com>
- Daniel Roe ([@danielroe](http://github.com/danielroe))
- Max ([@onmax](http://github.com/onmax))

## v0.0.22

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.21...v0.0.22)

### 🚀 Enhancements

- Add `redirectUrl` to OAuthMicrosoftConfig for HTTP vs HTTPS Handling ([50ba6fe](https://github.com/Atinux/nuxt-auth-utils/commit/50ba6fe))

### 🩹 Fixes

- **types:** Narrowed session type passed to fetch session hook ([77c82e7](https://github.com/Atinux/nuxt-auth-utils/commit/77c82e7))

### 📖 Documentation

- Use new nuxi module add command in installation ([d64b9d3](https://github.com/Atinux/nuxt-auth-utils/commit/d64b9d3))
- Improve readme ([00c8287](https://github.com/Atinux/nuxt-auth-utils/commit/00c8287))

### ❤️ Contributors

- Gerben Mulder <github.undergo381@passmail.net>
- André Agro Ferreira ([@andreagroferreira](http://github.com/andreagroferreira))
- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Daniel Roe ([@danielroe](http://github.com/danielroe))

## v0.0.21

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.20...v0.0.21)

### 🏡 Chore

- Update deps ([c8b8eb9](https://github.com/Atinux/nuxt-auth-utils/commit/c8b8eb9))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.20

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.19...v0.0.20)

### 🩹 Fixes

- Leverage NUXT_SESSION_PASSWORD provided at runtime ([4932959](https://github.com/Atinux/nuxt-auth-utils/commit/4932959))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.19

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.18...v0.0.19)

### 🚀 Enhancements

- Generate NUXT_SESSION_PASSWORD and throw if not set in production ([de890ed](https://github.com/Atinux/nuxt-auth-utils/commit/de890ed))

### 🩹 Fixes

- Leverage runtimeConfig to check password ([7c23543](https://github.com/Atinux/nuxt-auth-utils/commit/7c23543))

### 🏡 Chore

- Fix types ([34dfb7b](https://github.com/Atinux/nuxt-auth-utils/commit/34dfb7b))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.18

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.16...v0.0.18)

### 🚀 Enhancements

- Add authorizationParams in oauth config ([#56](https://github.com/Atinux/nuxt-auth-utils/pull/56))

### 🩹 Fixes

- UserSession user type augmentation ([#54](https://github.com/Atinux/nuxt-auth-utils/pull/54))
- User session types ([#55](https://github.com/Atinux/nuxt-auth-utils/pull/55))

### 📖 Documentation

- Update badge colors ([ff868a6](https://github.com/Atinux/nuxt-auth-utils/commit/ff868a6))

### 🏡 Chore

- Update deps ([fdaa88c](https://github.com/Atinux/nuxt-auth-utils/commit/fdaa88c))
- Add api test route ([9aed7fe](https://github.com/Atinux/nuxt-auth-utils/commit/9aed7fe))
- Update deps in playground ([95c657f](https://github.com/Atinux/nuxt-auth-utils/commit/95c657f))
- **release:** V0.0.17 ([a814b58](https://github.com/Atinux/nuxt-auth-utils/commit/a814b58))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Gerben Mulder ([@Gerbuuun](http://github.com/Gerbuuun))

## v0.0.17

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.16...v0.0.17)

### 🩹 Fixes

- UserSession user type augmentation ([#54](https://github.com/Atinux/nuxt-auth-utils/pull/54))

### 🏡 Chore

- Update deps ([fdaa88c](https://github.com/Atinux/nuxt-auth-utils/commit/fdaa88c))
- Add api test route ([9aed7fe](https://github.com/Atinux/nuxt-auth-utils/commit/9aed7fe))
- Update deps in playground ([95c657f](https://github.com/Atinux/nuxt-auth-utils/commit/95c657f))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Gerben Mulder ([@Gerbuuun](http://github.com/Gerbuuun))

## v0.0.16

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.15...v0.0.16)

### 🚀 Enhancements

- Add replaceUserSession() ([#44](https://github.com/Atinux/nuxt-auth-utils/pull/44))

### 🩹 Fixes

- **google:** Remove `redirectUrl` type ([#52](https://github.com/Atinux/nuxt-auth-utils/pull/52))

### 🏡 Chore

- Better server types ([#51](https://github.com/Atinux/nuxt-auth-utils/pull/51))
- Update deps ([b930118](https://github.com/Atinux/nuxt-auth-utils/commit/b930118))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Maximilian Götz-Mikus ([@maximilianmikus](http://github.com/maximilianmikus))
- Harlan Wilton ([@harlan-zw](http://github.com/harlan-zw))

## v0.0.15

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.14...v0.0.15)

### 🚀 Enhancements

- Add auth0 connection parameter to config ([#39](https://github.com/Atinux/nuxt-auth-utils/pull/39))
- Added aws cognito provider ([#36](https://github.com/Atinux/nuxt-auth-utils/pull/36))

### 🩹 Fixes

- Replace encoded space characters with regular spaces ([#40](https://github.com/Atinux/nuxt-auth-utils/pull/40))

### 🏡 Chore

- Up deps ([a7bd06b](https://github.com/Atinux/nuxt-auth-utils/commit/a7bd06b))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Dvir Hazout <dvir@dazz.io>
- Silvio Eckl <silvio@whitespace.no>
- Ahmed Rangel ([@ahmedrangel](http://github.com/ahmedrangel))

## v0.0.14

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.13...v0.0.14)

### 🚀 Enhancements

- Added keycloak as oauth provider ([#23](https://github.com/Atinux/nuxt-auth-utils/pull/23))

### 🏡 Chore

- Test bundler module resolution ([#32](https://github.com/Atinux/nuxt-auth-utils/pull/32))
- Update deps ([9d6b258](https://github.com/Atinux/nuxt-auth-utils/commit/9d6b258))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Yue JIN 
- Daniel Roe <daniel@roe.dev>

## v0.0.13

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.12...v0.0.13)

### 🏡 Chore

- Rename session from verify to fetch ([10694e9](https://github.com/Atinux/nuxt-auth-utils/commit/10694e9))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.12

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.11...v0.0.12)

### 🩹 Fixes

- Correct arguments for hooks ([6e0193e](https://github.com/Atinux/nuxt-auth-utils/commit/6e0193e))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.11

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.10...v0.0.11)

### 🚀 Enhancements

- Add sessionHooks to extend user sessions ([c470319](https://github.com/Atinux/nuxt-auth-utils/commit/c470319))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.10

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.9...v0.0.10)

### 🚀 Enhancements

- Added linkedIn auth provider ([#13](https://github.com/Atinux/nuxt-auth-utils/pull/13))

### 🩹 Fixes

- Add audience to auth0 runtime config types ([#27](https://github.com/Atinux/nuxt-auth-utils/pull/27))

### 📖 Documentation

- Add LinkedIn in providers ([c9b9925](https://github.com/Atinux/nuxt-auth-utils/commit/c9b9925))

### 🏡 Chore

- Update deps ([bb3a510](https://github.com/Atinux/nuxt-auth-utils/commit/bb3a510))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- José Manuel Madriaza Caravia 
- H+ <serdar@justserdar.dev>

## v0.0.9

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.8...v0.0.9)

### 🚀 Enhancements

- Add max_age param for auth0 ([#26](https://github.com/Atinux/nuxt-auth-utils/pull/26))
- Added Microsoft as oauth provider ([#8](https://github.com/Atinux/nuxt-auth-utils/pull/8))

### ❤️ Contributors

- Jakub Frelik <j.frelik.it@outlook.com>
- Uģis ([@BerzinsU](http://github.com/BerzinsU))

## v0.0.8

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.7...v0.0.8)

### 🩹 Fixes

- Avoid infinite loop with latest Nuxt ([93b949d](https://github.com/Atinux/nuxt-auth-utils/commit/93b949d))

### 🏡 Chore

- **playground:** Better with right title ([97a3ad3](https://github.com/Atinux/nuxt-auth-utils/commit/97a3ad3))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.7

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.6...v0.0.7)

### 🩹 Fixes

- **oauth:** Add generic OAuthConfig type ([#18](https://github.com/Atinux/nuxt-auth-utils/pull/18))

### 📖 Documentation

- Use consistent reference to module ([13daa78](https://github.com/Atinux/nuxt-auth-utils/commit/13daa78))

### 🏡 Chore

- Add SameSite=lax ([1b296e2](https://github.com/Atinux/nuxt-auth-utils/commit/1b296e2))

### ❤️ Contributors

- Sigve Hansen ([@sifferhans](http://github.com/sifferhans))
- Daniel Roe <daniel@roe.dev>
- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.6

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.5...v0.0.6)

### 🚀 Enhancements

- Added discord auth provider ([#7](https://github.com/Atinux/nuxt-auth-utils/pull/7))
- Added oauth battle.net ([#11](https://github.com/Atinux/nuxt-auth-utils/pull/11))
- Refactor login buttons to use dropdown ([#14](https://github.com/Atinux/nuxt-auth-utils/pull/14))

### 🏡 Chore

- Update deps ([05f4a9c](https://github.com/Atinux/nuxt-auth-utils/commit/05f4a9c))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Arash 
- Samuel LEFEVRE 
- H+ <serdar@darweb.nl>

## v0.0.5

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.4...v0.0.5)

### 🚀 Enhancements

- Added google as oauth provider ([#3](https://github.com/Atinux/nuxt-auth-utils/pull/3))
- Added twitch as supported oauth provider ([#5](https://github.com/Atinux/nuxt-auth-utils/pull/5))
- Added auth0 as oauth provider ([#6](https://github.com/Atinux/nuxt-auth-utils/pull/6))

### 💅 Refactors

- Use `useSession` generic rather than assertion ([#4](https://github.com/Atinux/nuxt-auth-utils/pull/4))

### 📖 Documentation

- Add demo ([cbc8b7a](https://github.com/Atinux/nuxt-auth-utils/commit/cbc8b7a))

### 🏡 Chore

- **release:** V0.0.4 ([2bc6f9a](https://github.com/Atinux/nuxt-auth-utils/commit/2bc6f9a))

### ❤️ Contributors

- Antoine Lassier <toinousp@gmail.com>
- Gerben Mulder ([@Gerbuuun](http://github.com/Gerbuuun))
- Ahmed Rangel ([@ahmedrangel](http://github.com/ahmedrangel))
- Akshara Hegde <akshara.dt@gmail.com>
- Sébastien Chopin ([@Atinux](http://github.com/Atinux))
- Daniel Roe ([@danielroe](http://github.com/danielroe))

## v0.0.4

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.3...v0.0.4)

### 🩹 Fixes

- Use import presets ([f16ebc9](https://github.com/Atinux/nuxt-auth-utils/commit/f16ebc9))

### 🏡 Chore

- **release:** V0.0.3 ([9d1342c](https://github.com/Atinux/nuxt-auth-utils/commit/9d1342c))
- Add comment ([1923dcc](https://github.com/Atinux/nuxt-auth-utils/commit/1923dcc))

### ❤️ Contributors

- Daniel Roe ([@danielroe](http://github.com/danielroe))
- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.3

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.2...v0.0.3)

### 🚀 Enhancements

- Allow users to define custom session factory + types ([#2](https://github.com/Atinux/nuxt-auth-utils/pull/2))

### 🩹 Fixes

- Don't log warning about password when preparing types ([804057b](https://github.com/Atinux/nuxt-auth-utils/commit/804057b))
- Import useRuntimeConfig ([bdbb4b8](https://github.com/Atinux/nuxt-auth-utils/commit/bdbb4b8))

### 🏡 Chore

- Remove `.nuxtrc` ([3f96e97](https://github.com/Atinux/nuxt-auth-utils/commit/3f96e97))
- Add type testing script ([e9ffa5e](https://github.com/Atinux/nuxt-auth-utils/commit/e9ffa5e))
- Move playground into workspace ([bd8108c](https://github.com/Atinux/nuxt-auth-utils/commit/bd8108c))
- Add playground type test ([74f452c](https://github.com/Atinux/nuxt-auth-utils/commit/74f452c))

### 🤖 CI

- Run lint + test actions in ci ([f50c1b5](https://github.com/Atinux/nuxt-auth-utils/commit/f50c1b5))

### ❤️ Contributors

- Daniel Roe ([@danielroe](http://github.com/danielroe))
- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

## v0.0.2

[compare changes](https://github.com/Atinux/nuxt-auth-utils/compare/v0.0.1...v0.0.2)

## v0.0.1


### 🩹 Fixes

- Workaround for addServerImportsDir not working ([5a189df](https://github.com/Atinux/nuxt-auth-utils/commit/5a189df))

### 📖 Documentation

- Update readme ([06f1504](https://github.com/Atinux/nuxt-auth-utils/commit/06f1504))

### 🏡 Chore

- Init ([19caed2](https://github.com/Atinux/nuxt-auth-utils/commit/19caed2))
- Add runtime config ([9013484](https://github.com/Atinux/nuxt-auth-utils/commit/9013484))
- V0 ([18ea43a](https://github.com/Atinux/nuxt-auth-utils/commit/18ea43a))
- Init ([9b75953](https://github.com/Atinux/nuxt-auth-utils/commit/9b75953))

### ❤️ Contributors

- Sébastien Chopin ([@Atinux](http://github.com/Atinux))

