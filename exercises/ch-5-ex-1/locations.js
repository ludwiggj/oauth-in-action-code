var client_port = 8000;
var authServer_port = 8001;
var resource_port = 8002;

// client information
var client = {
    "client_id": "oauth-client-1",
    "client_secret": "oauth-client-secret-1",
    "redirect_uris": [`http://localhost:${client_port}/callback`],
    "scope": "foo bar"
};

// authorization server information
var authServer = {
    authorizationEndpoint: `http://localhost:${authServer_port}/authorize`,
    tokenEndpoint: `http://localhost:${authServer_port}/token`,
    revocationEndpoint: `http://localhost:${authServer_port}/revoke`,
    registrationEndpoint: `http://localhost:${authServer_port}/register`,
    userInfoEndpoint: `http://localhost:${authServer_port}/userinfo`
};

// protected resource information
var protectedResource = `http://localhost:${resource_port}/resource`;

module.exports = {
    client: client,
    authServer: authServer,
    protectedResource: protectedResource,
    client_port: client_port,
    authServer_port: authServer_port,
    resource_port: resource_port
};