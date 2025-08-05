var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");

// Import locations and configuration
var locations = require('./locations.js');
var client = locations.client;
var authServer = locations.authServer;
var protectedResource = locations.protectedResource;
var client_port = locations.client_port;

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

var state = null;

var access_token = null;
var refresh_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

app.get('/authorize', function(req, res){
	access_token = null;
	refresh_token = null;
	scope = client.scope;
	state = randomstring.generate();
	
	var authorizeUrl = url.parse(authServer.authorizationEndpoint, true);
	delete authorizeUrl.search; // this is to get around odd behavior in the node URL library
	authorizeUrl.query.response_type = 'code';
	authorizeUrl.query.scope = client.scope;
	authorizeUrl.query.client_id = client.client_id;
	authorizeUrl.query.redirect_uri = client.redirect_uris[0];
	authorizeUrl.query.state = state;
	
	console.log("redirect", url.format(authorizeUrl));
	res.redirect(url.format(authorizeUrl));
});

app.get("/callback", function(req, res){
	
	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', {error: req.query.error});
		return;
	}
	
	var resState = req.query.state;
	if (resState == state) {
		console.log('State value matches: expected %s got %s', state, resState);
	} else {
		console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
		res.render('error', {error: 'State value did not match'});
		return;
	}

	var code = req.query.code;

	var form_data = qs.stringify({
				grant_type: 'authorization_code',
				code: code,
				redirect_uri: client.redirect_uri
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + Buffer.from(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);

	console.log('Requesting access token for code %s',code);
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
	
		access_token = body.access_token;
		console.log('Got access token: %s', access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}
		
		if (body.expires_in) {
			console.log('Access token expires in %s seconds', body.expires_in);
		}
		
		scope = body.scope;
		console.log('Got scope: %s', scope);

		res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
});

var refreshAccessToken = function(req, res) {
	// Authenticate via form fields this time...
	var form_data = qs.stringify({
				grant_type: 'refresh_token',
				refresh_token: refresh_token,
				client_id: client.client_id,
				client_secret: client.client_secret,
				redirect_uri: client.redirect_uri
			});

	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded'
	};

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);

	console.log('Requesting access token using refresh token %s',refresh_token);

	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());

		access_token = body.access_token;
		console.log('Got access token: %s', access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}
		
		if (body.expires_in) {
			console.log('Access token expires in %s seconds', body.expires_in);
		}
		
		scope = body.scope;
		console.log('Got scope: %s', scope);
	
		// Following borrowed from ch-3-ex-2/client.js
		// In this version, user is shown the tokens again, and can see that they have a new access and refresh token
		// User then just clicks on 'Get Protected Resource' button to access the resource
		// res.render('index', {access_token: access_token, scope: scope, refresh_token: refresh_token});

		// In this (improved) version, we just redirect to /fetch_resource, so we automatically retry the resource again,
		// having previously got a new access and refresh token
		res.redirect('/fetch_resource');
		return;
	} else {
		console.log('No refresh token, asking the user to get a new access token');
		res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
		return;
	}
};

app.get('/fetch_resource', function(req, res) {
	if (!access_token) {
		res.render('error', {error: 'Missing access token.'});
		return;
	}

	console.log('Making request with access token %s', access_token);
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('POST', protectedResource,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('data', {resource: body});
		return;
	} else {
		/*
		 * Following taken from ch-3-ex-2/client.js
		 * If we have a refresh token then refresh the access token and retry the resource request.
		 * Only give up if that fails
		 */
		access_token = null;
		console.log('Resource request failed with status code %s', resource.statusCode);
		if (refresh_token) {
			refreshAccessToken(req, res);
			return;
		} else {
			console.log("resource status error code " + resource.statusCode);
			res.render('error', {error: 'Unable to fetch resource. Status ' + resource.statusCode});
		}
	}
});

app.use('/', express.static('files/client'));

var server = app.listen(client_port, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
