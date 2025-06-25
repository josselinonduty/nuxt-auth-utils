import type { H3Event } from 'h3'
import { eventHandler, getQuery, sendRedirect } from 'h3'
import { withQuery } from 'ufo'
import { defu } from 'defu'
import { handleMissingConfiguration, handleAccessTokenErrorResponse, getOAuthRedirectURL, requestAccessToken, handleState, handleInvalidState } from '../utils'
import { useRuntimeConfig, createError } from '#imports'
import type { OAuthConfig } from '#auth-utils'

export interface OAuthPocketidConfig {
  /**
   * PocketId OAuth Client ID
   * @default process.env.NUXT_OAUTH_POCKETID_CLIENT_ID
   */
  clientId?: string
  /**
   * PocketId OAuth Client Secret
   * @default process.env.NUXT_OAUTH_POCKETID_CLIENT_SECRET
   */
  clientSecret?: string
  /**
   * PocketId OAuth Scope
   * @default ['id']
   * @example ['id']
   */
  scope?: string[]
  /**
   * PocketId MyDomain URL
   */
  baseURL?: string
  /**
   * PocketId OAuth Authorization URL
   */
  authorizationURL?: string
  /**
   * PocketId OAuth Authorization URL
   */
  tokenURL?: string
  /**
   * Extra authorization parameters to provide to the authorization URL
   * @default {}
   */
  authorizationParams?: Record<string, string>
  /**
   * Redirect URL to allow overriding for situations like prod failing to determine public hostname
   * @default process.env.NUXT_OAUTH_POCKETID_REDIRECT_URL or current URL
   */
  redirectURL?: string
}

export function defineOAuthPocketidEventHandler({
  config,
  onSuccess,
  onError,
}: OAuthConfig<OAuthPocketidConfig>) {
  return eventHandler(async (event: H3Event) => {
    const runtimeConfig = useRuntimeConfig(event).oauth?.pocketid
    const baseURL = config?.baseURL || runtimeConfig?.baseURL

    if (!baseURL) {
      return handleMissingConfiguration(event, 'pocketid', ['baseURL'], onError)
    }

    config = defu(config, runtimeConfig, {
      authorizationURL: `${baseURL}/authorize`,
      tokenURL: `${baseURL}/api/oidc/token`,
      authorizationParams: {},
    }) as OAuthPocketidConfig

    const query = getQuery<{ code?: string, state?: string, error?: string }>(event)

    if (query.error) {
      const error = createError({
        statusCode: 401,
        message: `Pocketid login failed: ${query.error || 'Unknown error'}`,
        data: query,
      })
      if (!onError) throw error
      return onError(event, error)
    }

    if (!config.clientId || !config.clientSecret || !baseURL) {
      return handleMissingConfiguration(event, 'pocketid', ['clientId', 'clientSecret'], onError)
    }

    const redirectURL = config.redirectURL || getOAuthRedirectURL(event)
    const state = await handleState(event)

    if (!query.code) {
      config.scope = config.scope || ['id']
      return sendRedirect(
        event,
        withQuery(config.authorizationURL as string, {
          response_type: 'code',
          client_id: config.clientId,
          redirect_uri: redirectURL,
          scope: config.scope.join(' '),
          state,
          ...config.authorizationParams,
        }),
      )
    }

    if (query.state !== state) {
      handleInvalidState(event, 'pocketid', onError)
    }

    const tokens = await requestAccessToken(config.tokenURL as string, {
      body: {
        grant_type: 'authorization_code',
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: redirectURL,
        code: query.code,
      },
    })

    if (tokens.error) {
      return handleAccessTokenErrorResponse(event, 'pocketid', tokens, onError)
    }

    const accessToken = tokens.access_token
    const user = await $fetch(`${baseURL}/api/oidc/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    return onSuccess(event, {
      user,
      tokens,
    })
  })
}
