import type { H3Event } from 'h3'
import { eventHandler, getQuery, sendRedirect } from 'h3'
import { withQuery } from 'ufo'
import { defu } from 'defu'
import { handleMissingConfiguration, handleAccessTokenErrorResponse, getOAuthRedirectURL, requestAccessToken } from '../utils'
import { useRuntimeConfig, createError } from '#imports'
import type { OAuthConfig } from '#auth-utils'

export interface OAuthRauthyConfig {
  /**
   * Rauthy OAuth Client ID
   * @default process.env.NUXT_OAUTH_RAUTHY_CLIENT_ID
   */
  clientId?: string
  /**
   * Rauthy OAuth Client Secret
   * @default process.env.NUXT_OAUTH_RAUTHY_CLIENT_SECRET
   */
  clientSecret?: string
  /**
   * Rauthy OAuth Server URL
   * @example http://192.168.1.10:8080
   * @default process.env.NUXT_OAUTH_RAUTHY_SERVER_URL
   */
  serverUrl?: string
  /**
   * Optional Rauthy OAuth Server URL to use internally, e.g. if Nuxt connects to a Docker hostname while the browser
   * redirect goes to localhost
   * @example http://rauthy:8080
   * @default process.env.NUXT_OAUTH_RAUTHY_SERVER_URL_INTERNAL
   */
  serverUrlInternal?: string
  /**
   * Rauthy OAuth Scope
   * @default []
   * @see https://www.rauthy.org/docs/latest/authorization_services/
   * @example ['openid']
   */
  scope?: string[]
  /**
   * Extra authorization parameters to provide to the authorization URL
   */
  authorizationParams?: Record<string, string>
  /**
   * Redirect URL to allow overriding for situations like prod failing to determine public hostname
   * @default process.env.NUXT_OAUTH_RAUTHY_REDIRECT_URL or current URL
   */
  redirectURL?: string
}

export function defineOAuthRauthyEventHandler({
  config,
  onSuccess,
  onError,
}: OAuthConfig<OAuthRauthyConfig>) {
  return eventHandler(async (event: H3Event) => {
    config = defu(config, useRuntimeConfig(event).oauth?.rauthy, {
      authorizationParams: {},
    }) as OAuthRauthyConfig

    const query = getQuery<{ code?: string, error?: string }>(event)

    if (query.error) {
      const error = createError({
        statusCode: 401,
        message: `Rauthy login failed: ${query.error || 'Unknown error'}`,
        data: query,
      })
      if (!onError) throw error
      return onError(event, error)
    }

    if (
      !config.clientId
      || !config.clientSecret
      || !config.serverUrl
    ) {
      return handleMissingConfiguration(event, 'rauthy', ['clientId', 'clientSecret', 'serverUrl'], onError)
    }

    const apiURL = `${config.serverUrl}/auth/v1`
    const apiURLInternal = `${config.serverUrlInternal || config.serverUrl}/auth/v1`

    const authorizationURL = `${apiURL}/oidc/authorize`
    const tokenURL = `${apiURLInternal}/oidc/token`
    const redirectURL = config.redirectURL || getOAuthRedirectURL(event)

    if (!query.code) {
      config.scope = config.scope || ['openid']

      // Redirect to Rauthy Oauth page
      return sendRedirect(
        event,
        withQuery(authorizationURL, {
          ...query,
          client_id: config.clientId,
          redirect_uri: redirectURL,
          scope: config.scope.join(' '),
          response_type: 'code',
          ...config.authorizationParams,
        }),
      )
    }

    config.scope = config.scope || []
    if (!config.scope.includes('openid')) {
      config.scope.push('openid')
    }

    const tokens = await requestAccessToken(tokenURL, {
      body: {
        grant_type: 'authorization_code',
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: redirectURL,
        code: query.code,
      } })

    if (tokens.error) {
      return handleAccessTokenErrorResponse(event, 'rauthy', tokens, onError)
    }

    const accessToken = tokens.access_token

    // TODO: improve typing
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const user: any = await $fetch(
      `${apiURL}/oidc/userinfo`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
      },
    )

    if (!user) {
      const error = createError({
        statusCode: 500,
        message: 'Could not get Rauthy user',
        data: tokens,
      })
      if (!onError) throw error
      return onError(event, error)
    }

    return onSuccess(event, {
      user,
      tokens,
    })
  })
}
