/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * Author: Amin Abbaspour
 * Date: 2025-01-02
 * License: MIT (https://github.com/auth0/client-initiated-account-linking/blob/main/LICENSE)
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */

const {ManagementClient, AuthenticationClient} = require('auth0');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const axios = require('axios');
const crypto = require('crypto');

const interactive_login = new RegExp('^oidc-');
const linking_resource_server = 'my-account';
const maxAllowedAge = 3600; // 60 minutes in seconds

const canPromptMfa = (user) => user.enrolledFactors && user.enrolledFactors.length > 0;
const hasDoneMfa = (event) => event.authentication.methods.some(m => m.name === 'mfa');
const mapEnrolledToFactors = (user) => user.enrolledFactors.map(f => f.method === 'sms' ? {
    type: 'phone', options: {preferredMethod: 'sms'}
} : {type: f.method});
//const linkedIdentityWithConnection = (user, connection) => user.identities.filter(i => i.connection === connection);
const makeNonce = (event) =>
    crypto.createHash('sha256').update(event.user.user_id + event.request.ip).digest('hex').substring(0, 32);

exports.onExecutePostLogin = async (event, api) => {

    const noop = api.noop || function (x) { // facilitate unit testing
        console.log(x);
    };

    const protocol = event?.transaction?.protocol || 'unknown';

    if (!interactive_login.test(protocol)) {
        return noop(`protocol is not interactive: ${protocol}`);
    }

    console.log(`protocol: ${protocol}, client_id: ${event.client.client_id}`);

    const {clientId} = event.secrets || {};

    if (event.client.client_id === clientId) {

        if (canPromptMfa(event.user) && !hasDoneMfa(event)) {
            console.log('mfa required in inner tx.')
            api.authentication.challengeWithAny(mapEnrolledToFactors(event.user));
        } else {
            console.log('mfa not required in inner tx.')
        }

        return noop('running inner transaction');
    }

    const {identifier: resource_server} = event?.resource_server;

    if (resource_server !== linking_resource_server) {
        return noop(`skip account linking. resource-server: ${resource_server}`);
    }

    const {requested_scopes} = event?.transaction;

    if (!Array.isArray(requested_scopes)) {
        return noop('requested scopes invalid');
    }

    const is_link_request = requested_scopes.includes('link_account');
    const is_unlink_request = requested_scopes.includes('unlink_account');

    if (!(is_link_request || is_unlink_request)) {
        return noop('no link_account or unlink_account scopes requested');
    }

    if (is_link_request && is_unlink_request) {
        return api.access.deny('both link_account and unlink_account requested');
    }

    const {id_token_hint} = event?.request?.query;

    if (!id_token_hint) {
        return api.access.deny('no id_token_hint present');
    }

    const {requested_connection, requested_connection_scopes} = event.request.query;

    if (!requested_connection) {
        return api.access.deny('no requested_connection requested');
    }

    let target_connection;
    let nonce;

    //const link_with_req_conn = linkedIdentityWithConnection(event.user, requested_connection);

    if (is_link_request) {
        /*
        if (link_with_req_conn.length > 0) { // already has a link with upstream connection ?
            return api.access.deny(`user has profile against connection ${requested_connection}`);
        }
        */
        target_connection = requested_connection;
        nonce = makeNonce(event);
    } else {
        const identity_with_req_conn = event.user.identities.filter(i => i.connection === requested_connection);

        if (!identity_with_req_conn || identity_with_req_conn.length === 0) {
            return api.access.deny(`user ${event.user.user_id} does not have profile against connection: ${requested_connection}`);
        }
        target_connection = event.user.identities[0].connection; // reauthenticate with the primary user connection
        nonce = `${identity_with_req_conn[0].connection}|${identity_with_req_conn[0].user_id}`; // TODO: this is unsafe
    }

    const {domain} = event.secrets || {};

    console.log(`account linking verifying id_token_hint: ${id_token_hint}`);

    let id_token;

    try {
        id_token = await verifyIdToken(api, id_token_hint, domain); // todo: optional auth_time claim check
    } catch (e) {
        console.log('account linking error during id_token verification', e);
        return api.access.deny('id_token_hint verification failed');
    }

    console.log(`account linking incoming id_token decoded: ${JSON.stringify(id_token)}`);

    if (id_token.sub !== event?.user?.user_id) {
        return api.access.deny(`sub mismatch. expected ${event?.user?.user_id} received ${id_token.sub}`);
    }

    console.log(`nonce for inner tx: ${nonce}`);

    // todo: PKCE
    const params = {
        client_id: clientId,
        redirect_uri: `https://${domain}/continue`, // TODO <-- HERE add this user's ID
        nonce,
        response_type: 'code',
        prompt: 'login',
        max_age: 0,
        connection: target_connection,
        login_hint: event.user.email,
        scope: 'openid profile email'
    };

    if (requested_connection_scopes)
        params.connection_scope = requested_connection_scopes;

    const nestedAuthorizeURL = buildAuthorizeUrl(domain, params);

    console.log(`account linking redirecting to: ${nestedAuthorizeURL}`);
    api.redirect.sendUserTo(nestedAuthorizeURL);
};

exports.onContinuePostLogin = async (event, api) => {
    //console.log(`onContinuePostLogin event: ${JSON.stringify(event)}`);
    const noop = api.noop || function (x) { // facilitate unit testing
        console.log(x);
    };

    const {domain, clientId, clientSecret} = event.secrets || {};

    const {code} = event.request.query;
    if (!code) {
        return api.access.deny(`missing code`);
    }

    const {identifier: resource_server} = event?.resource_server;

    if (resource_server !== linking_resource_server) {
        return api.access.deny(`invalid resource-server: ${resource_server}`);
    }

    const {requested_scopes} = event?.transaction;

    if (!Array.isArray(requested_scopes)) {
        return api.access.deny('requested scopes invalid');
    }

    const is_link_request = requested_scopes.includes('link_account');
    const is_unlink_request = requested_scopes.includes('unlink_account');

    if (!(is_link_request || is_unlink_request)) {
        return api.access.deny('no link_account or unlink_account scopes requested');
    }

    if (is_link_request && is_unlink_request) {
        return api.access.deny('both link_account and unlink_account requested');
    }

    let id_token_str;
    try {
        id_token_str = await exchange(domain, clientId, clientSecret, code, `https://${domain}/continue`);
    } catch (e) {
        console.log('account linking continue exchange error', e);
        return api.access.deny('error in exchange');
    }

    console.log(`account linking continue id_token string from exchange: ${id_token_str}`);

    if (!id_token_str) {
        return api.access.deny('error in exchange');
    }

    let id_token;

    try {
        id_token = await verifyIdToken(api, id_token_str, domain, clientId);
    } catch (e) {
        console.log('account linking continue id_token verify error', e);
        return api.access.deny('id_token verification failed');
    }

    /* optional check: If you are only linking users with the same email, you can uncomment this
    if (event.user.email !== id_token.email) {
        api.access.deny('emails do not match');
        return;
    }
    */

    console.log(`id_token for after continue exchange: ${JSON.stringify(id_token)}`);

    if (is_link_request) {

        if (id_token.nonce !== makeNonce(event)) {
            return api.access.deny('nonce mismatch');
        }

        if (event.user.user_id === id_token.sub) {
            return noop('user already linked');
        }

        // optional check: upstream to supply verified emails only
        if (id_token.email_verified !== true) {
            return api.access.deny('email not verified for nested user');
        }

        /*
        const identity_with_conn_id = event.user.identities.filter(i => i.provider === up_provider && i.user_id === up_user_id);

        if(identity_with_conn_id.length > 0) {
            return noop('user already linked');
        }
        */

        await linkAndMakePrimary(event, api, id_token.sub);
    } else {

        const sub_to_unlink = id_token.nonce; // I know this is not great, but...

        if (!sub_to_unlink) {
            return api.access.deny('missing user_id claim');
        }

        await unlink(event, api, sub_to_unlink);
    }
};

function buildAuthorizeUrl(domain, params) {
    const queryString = Object.keys(params)
        .map(k => `${k}=${encodeURIComponent(params[k])}`)
        .join("&");

    return `https://${domain}/authorize?${queryString}`;
}

async function getManagementClient(event, api) {

    const {domain} = event.secrets;

    let {value: token} = api.cache.get('management-token') || {};

    if (!token) {
        const {clientId, clientSecret} = event.secrets || {};

        const cc = new AuthenticationClient({domain, clientId, clientSecret});

        try {
            const {data} = await cc.oauth.clientCredentialsGrant({audience: `https://${domain}/api/v2/`});

            token = data?.access_token;

            if (!token) {
                console.log('failed get api v2 cc token');
                return;
            }
            console.log('cache MIS m2m token!');

            const result = api.cache.set('management-token', token, {ttl: data.expires_in * 1000});

            if (result?.type === 'error') {
                console.log('failed to set the token in the cache with error code', result.code);
            }
        } catch (err) {
            console.log('failed calling cc grant', err);
            return;
        }
    }

    return new ManagementClient({domain, token});
}

function splitSubClaim(sub) {
    const firstPipeIndex = sub.indexOf('|');
    return {provider: sub.slice(0, firstPipeIndex), user_id: sub.slice(firstPipeIndex + 1)};
}

async function linkAndMakePrimary(event, api, upstream_sub) {
    const client = await getManagementClient(event, api);
    const {user_id, provider} = event.user.identities[0];

    // Have either A or B

    // (A) this block links current user to upstream user, making this user secondary
    // (B) this block links current user to upstream user, keeping this user primary

    /*
        const firstPipeIndex = upstream_sub.indexOf('|');
        const [up_provider, up_user_id] = [upstream_sub.slice(0, firstPipeIndex), upstream_sub.slice(firstPipeIndex + 1)];
    */

    try {
        await client.users.link({id: `${provider}|${user_id}`}, splitSubClaim(upstream_sub));
        console.log(`link successful current user ${provider}|${user_id} to ${upstream_sub}`);
        // api.authentication.setPrimaryUser(upstream_sub);
    } catch (err) {
        console.log(`unable to link, no changes. error: ${JSON.stringify(err)}`);
        return api.access.deny('error linking');
    }
}

async function verifyIdToken(api, id_token, domain, client_id, nonce) {

    function getKey(header, callback) {
        const {value: signingKey} = api.cache.get(`key-${header.kid}`) || {};
        if (!signingKey) {
            console.log(`cache MIS signing key: ${header.kid}`);
            const client = jwksClient({
                jwksUri: `https://${domain}/.well-known/jwks.json`
            });

            client.getSigningKey(header.kid, (err, key) => {
                if (err) {
                    console.log('failed to download signing key: ', err.message);
                    return callback(err);
                }
                const signingKey = key.publicKey || key.rsaPublicKey;

                const result = api.cache.set(`key-${header.kid}`, signingKey);

                if (result?.type === 'error') {
                    console.log('failed to set signing key in the cache', result.code);
                }
                callback(null, signingKey);
            });
        } else {
            callback(null, signingKey);
        }
    }

    const signature = {
        issuer: `https://${domain}/`,
        algorithms: ['RS256'],
        maxAge: maxAllowedAge
    }

    if (nonce) {
        signature.nonce = nonce;
    }

    if (client_id) {
        signature.client_id = client_id;
    }

    return new Promise((resolve, reject) => {
        jwt.verify(id_token, getKey, signature, (err, decoded) => {
            if (err) reject(err);
            else resolve(decoded);
        });
    });
}

async function exchange(domain, client_id, client_secret, code, redirect_uri) {
    // console.log(`exchanging code: ${code}`);

    const {data: {id_token}} = await axios({
        method: 'post', url: `https://${domain}/oauth/token`, data: {
            client_id, client_secret, code, grant_type: 'authorization_code', redirect_uri
        }, headers: {
            'Content-Type': 'application/json'
        }, timeout: 5000 // 5 sec TODO configurable
    });

    return id_token;
}

async function unlink(event, api, sub) {

    const { provider: connection, user_id: user_id_to_unlink} = splitSubClaim(sub);

    console.log(`unlink connection: ${connection}, user_id_to_unlink: ${user_id_to_unlink}`);

    // Run the unlink function
    const unlinkIdentities = event.user.identities.filter(x => x.connection === connection && x.user_id === user_id_to_unlink);

    if (unlinkIdentities.length !== 1) {
        return api.access.deny('target identity not found');
    }

    const primary_id = event.user.user_id;
    const unlink_id = unlinkIdentities[0].user_id;

    console.log(`client initiated unlink Identity: ` + primary_id, connection, unlink_id);

    const client = await getManagementClient(event, api);

    try {
        await client.users.unlink({
            id: primary_id,       // Primary user ID (who has linked accounts)
            provider: connection, // e.g., "google-oauth2"
            user_id: unlink_id,   // ID of the linked account
        });
        console.log(`successfully unlinked identity ${connection}|${unlink_id} from primary: ${primary_id}`);
    } catch (err) {
        console.log(`unable to unlink, no changes. error: ${JSON.stringify(err)}`);
        api.access.deny('error unlinking');
    }
}
