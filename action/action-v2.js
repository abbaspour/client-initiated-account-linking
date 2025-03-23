/**
 * Implementation of [Client Initiated Account Linking](https://auth0.com/docs/manage-users/user-accounts/user-account-linking/user-initiated-account-linking-client-side-implementation) 
 * in an Auth0 Action. This action facilitates OIDC Applications to be able to 
 * request account linking from the Authorization Server instead of having to perform 
 * this in-app. 
 * 
 * To request account linking the application must send the following parameters
 * - `scope=link_account`, used to determine account linking is required
 * - `id_token_hint`, A valid `id_token` obtained for the client, that belongs to the user on 
 *   whose behalf the client initiated account linking is being requested 
 * - `requested_connection`, the provider which is requested.
 * - `requested_connection_scope`, OPTIONAL list of scopes that are requested by the provider, 
 *    if not present it will leverage the configured scopes in the Dashboard. 
 *
 * Author: Auth0 Product Architecture
 * Date: 2025-03-21
 * License: MIT (https://github.com/auth0/client-initiated-account-linking/blob/main/LICENSE)
 *
 * ## Required Secrets
 * 
 *  - `AUTH0_CLIENT_ID` Client ID for Regular Web Applicaton, this action is registered to
 *  - `AUTH0_CLIENT_SECRET` Client Secret for Regular Web Application, this action is registered to
 *  - `ACTION_SECRET` A secret that is unique to this application you can use `uuidgen` or a secure random string
 * 
 * ## Optional Secrets
 * 
 *  - ALLOWED_CLIENT_IDS Comma Separated List of all client ids, by default all clients may request when using OIDC
 *  - DEBUG, allows you to update and enable / disable optional logging during development.
 */

// Required Modules
const { ManagementClient, PostIdentitiesRequestProviderEnum } = require('auth0');
const client = require('openid-client');
const jose = require('jose');
const { createHash } = require('node:crypto');
const { URLSearchParams } = require('node:url');

// Global constants
const SCOPES = { 
  LINK: 'link_account'
};
const JWKS_CACHE_KEY = 'jwks-cache';
const MGMT_TOKEN_CACHE_KEY = 'management-token';

/**
 * This action should only run for OIDC/OAuth 2 Flows
 * @type {Protocol[]} 
 */
const ALLOWED_PROTOCOLS = [
  'oidc-basic-profile',
  'oidc-implicit-profile',
  'oauth2-device-code',
  'oidc-hybrid-profile'
];
// End Global Constants

/**
 * Initial Handler
 * 
 * @param {PostLoginEvent} event 
 * @param {PostLoginAPI} api 
 * @returns 
 */
exports.onExecutePostLogin = async (event, api) => {
  if (isLinkingRequest(event)) {
    const jwksCache = extractCachedJWKS(event, api);
    const response = await validateIdTokenHint(event, api, jwksCache);
    if (response === 'invalid') {
      api.access.deny('ID_TOKEN_HINT Invalid: The `id_token_hint` does not conform to the authorization policy');
      return;
    }
    return handleLinkingRequest(event, api);
  }
};

/**
 * Callback handler 
 * 
 * @param {PostLoginEvent} event 
 * @param {PostLoginAPI} api 
 * @returns 
 */
exports.onContinuePostLogin = async (event, api) => {
  if (isLinkingRequest(event)) {
    return handleLinkingCallback(event, api);
  }
};

// Helper Utilities

/**
 * Check's if this an Account Linking Request
 * 
 * @param {PostLoginEvent} event
 */
function isLinkingRequest(event) {
  if (!event.transaction || !event.transaction.protocol) {
    console.warn('Skipping because no transaction');
    return false;
  }

  if (ALLOWED_PROTOCOLS.includes(event.transaction.protocol) === false) {
    console.warn('Skipping because protocol not allowed');
    return false;
  }

  const { requested_scopes } = event.transaction;

  if (!Array.isArray(requested_scopes)) {
    console.warn('Skipping because requested_scopes not found');
    return false;
  }

  if (!requested_scopes.includes(SCOPES.LINK)) {
    console.warn('Skipping because requested_scopes does not contain link_account');
    return false;
  }

  return true;
}

/**
 * 
 * @param {PostLoginEvent} event
 * @param {PostLoginAPI} api
 */
async function handleLinkingRequest(event, api) {
  const issuer = getAuth0Issuer(event);

  const {
    requested_connection: requestedConnection,
    requested_connection_scope: requestedConnectionScope,
  } = event.request.query;

  const codeVerifier = await getUniqueTransaction(event);
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  const jwksCache = extractCachedJWKS(event, api);
  const config = await getOpenIDClientConfig(event, api, jwksCache);

  /**
   * @type {Record<string, string>}
   */
  const authorizationParameters = {
    redirect_uri: (new URL('/continue', issuer)).toString(), // TODO <-- HERE add this user's ID
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    connection: requestedConnection,
    scope: 'openid profile email', // this scope is for the auth0 transaction
  };

  if (requestedConnectionScope) {
    // This scope is for the transaction
    authorizationParameters['connection_scope'] = requestedConnectionScope;
  }

  const authorizeUrl = client.buildAuthorizationUrl(config, authorizationParameters);
  api.redirect.sendUserTo(authorizeUrl.toString());
}

/**
 * 
 * @param {PostLoginEvent} event
 * @param {PostLoginAPI} api
 */
async function handleLinkingCallback(event, api) {
  const callbackUrl = getCallbackUrl(event);
  const jwksCacheInput = extractCachedJWKS(event, api);
  const config = await getOpenIDClientConfig(event, api, jwksCacheInput);
  const codeVerifier = await getUniqueTransaction(event);
  let subject;

  try {
    const jwksCacheInput = extractCachedJWKS(event, api);
    const tokens = await client.authorizationCodeGrant(config, callbackUrl, {
      expectedState: client.skipStateCheck,
      idTokenExpected: true,
      maxAge: 60,
      pkceCodeVerifier: codeVerifier
    });

    const jwksCacheExport = client.getJwksCache(config);
    // Store cached JWTs
    if (jwksCacheExport && jwksCacheExport.uat !== jwksCacheInput?.uat) {
      storeCachedJWKS(event, api, jwksCacheExport);
    }

    const claims = tokens.claims();
    if (!claims) {
      console.warn('Failed: No claims');
      return;
    }
    
    subject = claims['sub'];
  } catch (err) {
    api.access.deny('Failed to complete account linking');
    return;
  }
 
  await linkAndMakePrimary(event, api, subject);
  
}


/**
 * Will obtain a cached JWKS from Actions Cache 
 * 
 * @param {PostLoginEvent} event 
 * @param {PostLoginAPI} api 
 * 
 * @returns {jose.ExportedJWKSCache | undefined} either a cached jwks or null. If this fails it'll fail gracefully
 */
function extractCachedJWKS(event, api) {
  try {
    const cachedJWKCache = api.cache.get(JWKS_CACHE_KEY);
    if (!cachedJWKCache) {
      return undefined;
    }
    /**
     * @type {jose.ExportedJWKSCache}
     */
    const value = JSON.parse(cachedJWKCache.value);
    return value;
  } catch (err) {
    // We should default to return null here
    // we can always fetch as fallback
  }
  return undefined;
}

/**
 * Will obtain a cached JWKS from Actions Cache 
 * 
 * @param {PostLoginEvent} event 
 * @param {PostLoginAPI} api 
 * @param {jose.ExportedJWKSCache} updated Exported JWKS cache
 */
function storeCachedJWKS(event, api, updated) {
  api.cache.set(JWKS_CACHE_KEY, JSON.stringify(updated));
}

/**
 * Helper function to return a client from openid-client. This is used  
 * for all the requests.
 * 
 * @param {PostLoginEvent} event 
 * @param {PostLoginAPI} api 
 * @param {jose.ExportedJWKSCache | undefined} jwksCacheInput
 * 
 * @returns {Promise<client.Configuration>}
 */
async function getOpenIDClientConfig(event, api, jwksCacheInput) {
  const issuer = getAuth0Issuer(event);
  const { 
    AUTH0_CLIENT_ID: clientId, 
    AUTH0_CLIENT_SECRET: clientSecret 
  } = event.secrets;
  const config =  await client.discovery(
    issuer, 
    clientId, 
    {}, 
    client.ClientSecretPost(clientSecret),
    {
      algorithm: 'oidc',
    }
  );
  
  if (jwksCacheInput !== undefined) {
    client.setJwksCache(config, jwksCacheInput);
  }

  return config;
}

/**
 * returns the callback url
 * 
 * @param {PostLoginEvent} event
 * @returns {URL}
 */
function getCallbackUrl(event) {
  const callbackUrl = new URL('/continue', getAuth0Issuer(event));
  callbackUrl.search = (new URLSearchParams(event.request.query)).toString();

  return callbackUrl;
}

/**
 * This method implements the following logic
 * 
 * - Ensure the `id_token_hint` is a valid `id_token`.
 * - Ensure the `client_id` in `id_token` matches the `client_id` of `event`.
 * - Ensure the `id_token` was issued to one of the event.secrets.ALLOWED_CLIENTs
 * - Ensure the `user_id` of the current `event.user` is the same as current user
 * - @todo: Ensure the `sid` in the `id_token` matches `event.session`
 * 
 * 
 * @param {PostLoginEvent} event 
 * @param {PostLoginAPI} api 
 * @param {jose.ExportedJWKSCache | undefined} jwksCache
 * @returns {Promise<"invalid"|"valid">} `valid` if all constraints match, `invalid` if any constraint fail, 
 */
async function validateIdTokenHint(event, api, jwksCache) {
  
  const { id_token_hint: idTokenHint } = event.request.query;
  const issuer = getAuth0Issuer(event);

  if (!idTokenHint || typeof idTokenHint !== 'string') {
    return 'invalid';
  }

  const { client_id: clientId } = event.client;
  const { user_id: userId} = event.user;

  const jwksUrl = new URL('/.well-known/jwks.json', issuer);
  const JWKS = jose.createRemoteJWKSet(jwksUrl, {
    [jose.jwksCache]: jwksCache
  });

  try {
    await jose.jwtVerify(idTokenHint, JWKS, {
      algorithms: ['RS256'],
      audience: clientId,
      subject: userId,
      issuer: issuer.toString(),
      maxTokenAge: '10m'
    });  

    return 'valid';
  } catch (err) {
    //
  }

  return 'invalid';
}

/**
 * Helper function to get a cached management token and client.
 * 
 * @param {PostLoginEvent} event 
 * @param {PostLoginAPI} api 
 * @returns 
 */
async function getManagementClient(event, api) {
  let { value: token } = api.cache.get(MGMT_TOKEN_CACHE_KEY) || {};

  if (!token) {
    // we don't need the JWKS here.
    const config = await getOpenIDClientConfig(event, api, undefined);

    try {
      const tokenset = await client.clientCredentialsGrant(config, {
        audience: (new URL('/api/v2/', `https://${event.secrets.AUTH0_DOMAIN}`)).toString()
      });

      const {access_token: accessToken} = tokenset;
      token = accessToken;

      if (!token) {
        return null;
      }

      const result = api.cache.set(MGMT_TOKEN_CACHE_KEY, token, {
        ttl: (tokenset.expires_in - 60) * 1000,
      });

      if (result?.type === 'error') {
        console.warn(
          'failed to set the token in the cache with error code',
          result.code
        );
      }
    } catch (err) {
      console.log('failed calling cc grant', err);
      return null;
    }
  }

  return new ManagementClient({ 
    domain: getAuth0Issuer(event).hostname, 
    token
  });
}

/**
 * 
 * @param {string} sub 
 * @returns {{provider: PostIdentitiesRequestProviderEnum, user_id: string}}
 */
function splitSubClaim(sub) {
  const firstPipeIndex = sub.indexOf('|');
  const provider = /** @type {PostIdentitiesRequestProviderEnum} */(sub.slice(0, firstPipeIndex));

  return {
    provider,
    user_id: sub.slice(firstPipeIndex + 1),
  };
}

/**
 * Returns the current domain for the tenant
 * 
 * @param {PostLoginEvent} event 
 */
function getAuth0Issuer(event) {
  return new URL(`https://${event.request.hostname}/`);
}

/**
 * In order to determine this transaction can be executed only between the initial
 * and the continue handler. We need to derive a unique string
 * 
 * @todo: Review approach with @sandrinodimattia
 * 
 * @param {PostLoginEvent} event 
 */
async function getUniqueTransaction(event) {
  const {ACTION_SECRET: appSecret} = event.secrets;  
  return sha256(`${event.request.ip}:${event.transaction.id}:${event.user.user_id}:${appSecret}:${event.session.id}`);
}

/**
 * 
 * @param {PostLoginEvent} event 
 * @param {PostLoginAPI} api 
 * @param {string} upstream_sub 
 * @returns 
 */
async function linkAndMakePrimary(event, api, upstream_sub) {
  const client = await getManagementClient(event, api);

  if (client === null) {
    api.access.deny('Failed to link users');
    return;
  }

  const { user_id, provider } = event.user.identities[0];

  // Have either A or B

  // (A) this block links current user to upstream user, making this user secondary
  // (B) this block links current user to upstream user, keeping this user primary

  try {
    await client.users.link(
      { id: `${provider}|${user_id}` },
      splitSubClaim(upstream_sub)
    );
    console.log(
      `link successful current user ${provider}|${user_id} to ${upstream_sub}`
    );
    // api.authentication.setPrimaryUser(upstream_sub);
  } catch (err) {
    console.log(`unable to link, no changes. error: ${JSON.stringify(err)}`);
    return api.access.deny('error linking');
  }
}

/**
 * 
 * @param {string} str
 */
function sha256(str) {
  return createHash('sha256').update(str).digest('base64url');
}

// End: Helper Utilities