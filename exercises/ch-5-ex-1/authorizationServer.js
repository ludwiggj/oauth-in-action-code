var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

// Import locations and configuration
var locations = require('./locations.js');
var authServer = locations.authServer;
var clients = [locations.client]; // Convert single client to array format
var authServer_port = locations.authServer_port;

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

// Display all access tokens by client ID
app.get('/tokens', function(req, res) {
	console.log('Displaying tokens page');
	
	// Get all tokens from the database
	nosql.find().make(function(builder) {
		builder.callback(function(err, allRecords) {
			if (err) {
				console.log('Error retrieving tokens:', err);
				res.render('error', {error: 'Error retrieving tokens'});
				return;
			}
			
			// Filter to only get access tokens (records that have access_token field but not refresh_token field)
			var tokens = allRecords.filter(function(record) {
				return record.access_token && !record.refresh_token;
			});
			
			// Filter to get refresh tokens (records that have refresh_token field but not access_token field)
			var refreshTokens = allRecords.filter(function(record) {
				return record.refresh_token && !record.access_token;
			});
			
			var now = new Date();
			var clientTokens = {};
			var clientRefreshTokens = {};
			
			// Group refresh tokens by client_id
			refreshTokens.forEach(function(token) {
				var clientId = token.client_id || 'unknown';
				
				if (!clientRefreshTokens[clientId]) {
					clientRefreshTokens[clientId] = {
						tokens: []
					};
				}
				
				var refreshTokenInfo = {
					refresh_token: token.refresh_token,
					client_id: token.client_id,
					scope: token.scope || 'No scope'
				};
				
				clientRefreshTokens[clientId].tokens.push(refreshTokenInfo);
			});
			
			// Group tokens by client_id and add status information
			tokens.forEach(function(token) {
				var clientId = token.client_id || 'unknown';
				
				if (!clientTokens[clientId]) {
					clientTokens[clientId] = {
						tokens: []
					};
				}
				
				// Check if token is expired
				var isExpired = false;
				var timeRemaining = null;
				
				if (token.expires_at) {
					var expiresAt = new Date(token.expires_at);
					isExpired = now > expiresAt;
					
					if (!isExpired) {
						var diffMs = expiresAt - now;
						var diffSecs = Math.floor(diffMs / 1000);
						var diffMins = Math.floor(diffSecs / 60);
						var diffHours = Math.floor(diffMins / 60);
						
						if (diffHours > 0) {
							timeRemaining = diffHours + 'h ' + (diffMins % 60) + 'm ' + (diffSecs % 60) + 's';
						} else if (diffMins > 0) {
							timeRemaining = diffMins + 'm ' + (diffSecs % 60) + 's';
						} else {
							timeRemaining = diffSecs + 's';
						}
					}
				}
				
				// Add formatted dates and status
				var tokenInfo = {
					access_token: token.access_token,
					client_id: token.client_id,
					expires_at: token.expires_at ? new Date(token.expires_at).toLocaleString() : null,
					issued_at: token.issued_at ? new Date(token.issued_at).toLocaleString() : null,
					scope: token.scope || 'No scope',
					is_expired: isExpired,
					time_remaining: timeRemaining
				};
				
				clientTokens[clientId].tokens.push(tokenInfo);
			});
			
			// Sort tokens by expiration date within each client
			Object.keys(clientTokens).forEach(function(clientId) {
				clientTokens[clientId].tokens.sort(function(a, b) {
					if (!a.expires_at && !b.expires_at) return 0;
					if (!a.expires_at) return 1;
					if (!b.expires_at) return -1;
					return new Date(a.expires_at) - new Date(b.expires_at);
				});
			});
			
			res.render('tokens', {
				tokens: tokens,
				clientTokens: clientTokens,
				clientRefreshTokens: clientRefreshTokens,
				now: now.toLocaleString()
			});
		});
	});
});

// Delete a specific access token
app.post('/delete-token', function(req, res) {
	var accessToken = req.body.access_token;
	
	if (!accessToken) {
		console.log('No access token provided for deletion');
		res.status(400).json({error: 'Missing access token'});
		return;
	}
	
	console.log('Deleting access token: %s', accessToken);
	
	// Remove the token from the database
	nosql.remove().make(function(builder) {
		builder.where('access_token', accessToken);
		builder.callback(function(err, count) {
			if (err) {
				console.log('Error deleting token:', err);
				res.status(500).json({error: 'Failed to delete token'});
				return;
			}
			
			if (count > 0) {
				console.log('Successfully deleted %d token(s)', count);
			} else {
				console.log('No token found to delete');
			}
			
			// Redirect back to the tokens page to show updated state
			res.redirect('/tokens');
		});
	});
});

// Generate a new access token from a refresh token
app.post('/generate-access-token', function(req, res) {
	var refreshToken = req.body.refresh_token;
	var clientId = req.body.client_id;
	var requestedScope = req.body.scope;
	
	if (!refreshToken) {
		console.log('No refresh token provided');
		res.status(400).json({error: 'Missing refresh token'});
		return;
	}
	
	console.log('Generating access token from refresh token: %s', refreshToken);
	
	// Find the refresh token in the database
	nosql.find().make(function(builder) {
		builder.where('refresh_token', refreshToken);
		builder.callback(function(err, records) {
			if (err) {
				console.log('Error finding refresh token:', err);
				res.status(500).json({error: 'Database error'});
				return;
			}
			
			if (!records || records.length === 0) {
				console.log('Refresh token not found');
				res.status(404).json({error: 'Refresh token not found'});
				return;
			}
			
			var refreshTokenRecord = records[0];
			
			// Validate client_id matches
			if (refreshTokenRecord.client_id !== clientId) {
				console.log('Client ID mismatch');
				res.status(400).json({error: 'Invalid client'});
				return;
			}
			
			// Validate requested scope is subset of original scope
			var originalScopes = refreshTokenRecord.scope || [];
			var requestedScopes = requestedScope ? requestedScope.split(' ') : [];
			
			var validScope = requestedScopes.every(function(scope) {
				return originalScopes.indexOf(scope) !== -1;
			});
			
			if (!validScope) {
				console.log('Requested scope exceeds original scope');
				res.status(400).json({error: 'Invalid scope'});
				return;
			}
			
			// Generate new access token
			var token_response = createTokenResponse(clientId, refreshToken, requestedScopes);
			
			console.log('Generated new access token from refresh token');
			res.json({success: true, token_response: token_response});
		});
	});
});

// Process the request, validate the client, and send the user to the approval page
app.get("/authorize", function(req, res){
	var client = getClient(req.query.client_id);
	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {
		var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
		var cscope = client.scope ? client.scope.split(' ') : undefined;

		if (__.difference(rscope, cscope).length > 0) {
			var urlParsed = buildUrl(req.query.redirect_uri, {
				error: 'invalid_scope'
			});
			res.redirect(urlParsed);
			return;
		}
		var reqid = randomstring.generate(8);
		requests[reqid] = req.query;
		res.render('approve', {client: client, reqid: reqid, scope: rscope});
		return;
	}
});

var getScopesFromForm = function(body) {
	return __.filter(
		__.keys(body), function(s) { 
			return __.string.startsWith(s, 'scope_');
		}
	)
	.map(function(s) {
		return s.slice('scope_'.length); 
	});
};

// Process the results of the approval page, authorize the client
app.post('/approve', function(req, res) {
	console.log('Processing approval for request %s', req.body.reqid);
	
	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];
	
	if (!query) {
		res.render('error', {error: 'No matching authorization request'})
		return;
	}

	if (req.body.approve) {
		// User approved access
		if (query.response_type == 'code') {
			var rscope = getScopesFromForm(req.body);
			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;

			if (__.difference(rscope, cscope).length > 0) {
				var urlParsed = buildUrl(req.query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}
		
			var code = randomstring.generate(8);
			codes[code] = { request: query, scope: rscope };
			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
		} else {
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
	} else {
		// User denied access
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}
});

// Generate an access token and store it so that we can look it up later.
var createTokenResponse = function(clientId, existing_refresh_token, scope) {
	// Access token is opaque in this example, but could be a JWT or other format.
	var access_token = randomstring.generate();
	var expires_in = 30;
	var issued_at = new Date(); // current timestamp
	var expires_at = new Date(issued_at.getTime() + expires_in * 1000); // expiration timestamp
				
	nosql.insert({ 
		access_token: access_token, 
		client_id: clientId,
		issued_at: issued_at,
		expires_at: expires_at,
		scope: scope
	});
	
	console.log('Issuing access token %s, issued at %s, expires at %s', access_token, issued_at, expires_at);

	var refresh_token = existing_refresh_token;
	if (!refresh_token) {
		// Generate a new refresh token if we don't have one already
		refresh_token = randomstring.generate();
		nosql.insert({ refresh_token: refresh_token, client_id: clientId, scope: scope });

		console.log('Issuing refresh token %s', refresh_token);
	} else {
		console.log('Reusing existing refresh token %s', refresh_token);
	}
	
	var token_response = { 
		access_token: access_token, 
		token_type: 'Bearer',
		expires_in: expires_in,
		refresh_token: refresh_token,
		scope: scope.join(' ')
	};
	
	console.log('Issued access token %s with refresh token %s', access_token, refresh_token);

	return token_response
}

// Process the request, issue an access token
app.post("/token", function(req, res){
	var auth = req.headers['authorization'];
	if (auth) {
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}

	if (req.body.client_id) {
		if (clientId) {
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}

	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	if (req.body.grant_type == 'authorization_code') {
		var code = codes[req.body.code];
		if (code) { 
			// Process the valid authorization code in here

			// Code is removed from storage as soon as we know the code is a valid one
			// regardless of the rest of the processing. This to err on the side of
			// caution, because a stolen authorization code presented by a bad client
			// should be considered lost.
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {
				var token_response = createTokenResponse(clientId, req.body.refresh_token, code.scope);
				console.log('Issued tokens for code %s', req.body.code);

				res.status(200).json(token_response);
				return;
			} else {
				// code was issued to a different client
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
	} else if (req.body.grant_type == 'refresh_token') {
		// lookup refresh token in internal database
		nosql.one().make(function(builder) {
			builder.where('refresh_token', req.body.refresh_token);
			builder.callback(function(err, token) {
				if (token) {
					console.log("We found a matching refresh token: %s", req.body.refresh_token);
					if (token.client_id != clientId) {
						nosql.remove().make(function(builder) { builder.where('refresh_token', req.body.refresh_token); });
						res.status(400).json({error: 'invalid_grant'});
						return;
					} else {
						var token_response = createTokenResponse(clientId, req.body.refresh_token, token.scope);
						res.status(200).json(token_response);
						return;
					}
				} else {
					res.status(400).json({error: 'invalid_grant'});
					return;
				};
			})
		});
	}
	else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
		return;
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(authServer_port, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
