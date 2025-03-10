const {expect, describe, it, beforeEach} = require('@jest/globals');
const {jest: _jest} = require('@jest/globals');

// Mock the necessary objects and methods
_jest.mock('axios');
_jest.mock('jwks-rsa');
_jest.mock('auth0');

_jest.mock('jsonwebtoken', () => ({
    verify: _jest.fn().mockImplementation(() => {
        //throw new Error('Invalid token');
        return {sub: 'auth0|123', auth_time: Math.floor(Date.now() / 1000)};
    }),
}));

describe('onExecutePostLogin', () => {
    let mockEvent;
    let mockApi;

    beforeEach(() => {
        // Reset the mocks before each test
        _jest.resetModules();

        // Mock event and API objects
        mockEvent = {
            transaction: {
                protocol: 'oidc-protocol',
                id: 'tx-id',
                requested_scopes: ['link_account']
            },
            connection: {
                strategy: 'custom-strategy',
            },
            user: {
                identities: [],
                user_id: 'auth0|123',
                email: 'test@example.com',
            },
            client: {
                client_id: 'testClientId',
            },
            secrets: {
                domain: 'test.auth0.com',
                clientId: 'companionClientId'
            },
            resource_server: {
                identifier: 'my-account'
            },
            request: {
                ip: '1.2.3.4',
                query: {
                    id_token_hint: 'some_id_token',
                    requested_connection: 'google-oauth2'
                }
            },
        };

        mockApi = {
            redirect: {
                sendUserTo: _jest.fn(),
            },
        };
    });

    it('should redirect to nestedAuthorizeURL', async () => {

        const {onExecutePostLogin} = require('../action/action');

        await onExecutePostLogin(mockEvent, mockApi);

        // Expect sendUserTo to be called with the correct URL
        expect(mockApi.redirect.sendUserTo).toHaveBeenCalledWith(
            // eslint-disable-next-line
            expect.stringContaining("https://test.auth0.com/authorize?client_id=companionClientId&redirect_uri=https%3A%2F%2Ftest.auth0.com%2Fcontinue&nonce=cb2515ab1456f97027c903f2702f7d06&response_type=code&prompt=login&max_age=0&connection=google-oauth2&login_hint=test%40example.com&scope=openid%20profile%20email%20undefined&auth0Client=eyJuYW1lIjoiYXV0aDAuanMiLCJ2ZXJzaW9uIjoiOS4yOC4wIn0%3D")
        );
    });

    it('should redirect for auth0 strategy', async () => {
        // Modify the event to have 'auth0' strategy
        mockEvent.connection.strategy = 'auth0';

        const {onExecutePostLogin} = require('../action/action');

        await onExecutePostLogin(mockEvent, mockApi);

        // Expect sendUserTo not to be called
        expect(mockApi.redirect.sendUserTo).toHaveBeenCalled();
    });

    it('should not redirect for interactive_login protocol', async () => {
        // Modify the event to have 'interactive_login' protocol
        mockEvent.transaction.protocol = 'interactive_login';

        const {onExecutePostLogin} = require('../action/action');

        await onExecutePostLogin(mockEvent, mockApi);

        // Expect sendUserTo not to be called
        expect(mockApi.redirect.sendUserTo).not.toHaveBeenCalled();
    });

});

