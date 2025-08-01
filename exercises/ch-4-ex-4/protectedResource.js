var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var __ = require('underscore');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

var getAccessToken = function(req, res, next) {
	var inToken = null;
	var auth = req.headers['authorization'];
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
	}
	
	console.log('Incoming token: %s', inToken);
	nosql.one().make(function(builder) {
	  builder.where('access_token', inToken);
	  builder.callback(function(err, token) {
	    if (token) {
	      console.log("We found a matching token: %s", inToken);
	    } else {
	      console.log('No matching token was found.');
	    };
	    req.access_token = token;
	    next();
	    return;
	  });
	});
};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
};

app.get('/favorites', getAccessToken, requireAccessToken, function(req, res) {
	
	/*
	 * Get different user information based on the information of who approved the token
	 */

	console.log('Access token %s with scopes: %s', req.access_token, req.access_token.scope.join(' '));

	if (req.access_token.user == 'alice') {
		var favorites = {movies: [], foods: [], music: []};
		if (__.contains(req.access_token.scope, 'movies')) {
		  favorites.movies = ['The Multidmensional Vector', 'Space Fights', 'Jewelry Boss'];
		}
		if (__.contains(req.access_token.scope, 'foods')) {
		  favorites.foods = ['bacon', 'pizza', 'bacon pizza'];
		}
		if (__.contains(req.access_token.scope, 'music')) {
		  favorites.music = ['techno', 'industrial', 'alternative'];
		}
		res.json({user: 'Alice', favorites: favorites});
    } else if (req.access_token.user == 'bob') {
		var favorites = {movies: [], foods: [], music: []};
		if (__.contains(req.access_token.scope, 'movies')) {
		  favorites.movies = ['An Unrequited Love', 'Several Shades of Turquoise', 'Think Of The Children'];
		}
		if (__.contains(req.access_token.scope, 'foods')) {
		  favorites.foods = ['bacon', 'kale', 'gravel'];
		}
		if (__.contains(req.access_token.scope, 'music')) {
		  favorites.music = ['baroque', 'ukulele', 'baroque ukulele'];
		}
      res.json({user: 'Bob', favorites: favorites});
    } else {
      var unknown = {user: 'Unknown', favorites: {movies: [], foods: [], music: []}};
      res.json(unknown);
    }
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
