/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util');


/**
 * Creates an instance of `Strategy`.
 *
 * The HTTP Bearer authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field, `access_token`
 * body parameter, or `access_token` query parameter.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(token, done) { ... }
 *
 * `token` is the bearer token provided as a credential.  The verify callback
 * is responsible for finding the user who possesses the token, and invoking
 * `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * If the token is not valid, `user` should be set to `false` to indicate an
 * authentication failure.  Additional token `info` can optionally be passed as
 * a third argument, which will be set by Passport at `req.authInfo`, where it
 * can be used by later middleware for access control.  This is typically used
 * to pass any scope associated with the token.
 *
 * Options:
 *
 *   - `realm`  authentication realm, defaults to "Users"
 *   - `scope`  list of scope values indicating the required scope of the access
 *              token for accessing the requested resource
 *
 * Examples:
 *
 *     passport.use(new BearerStrategy(
 *       function(token, done) {
 *         User.findByToken({ token: token }, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user, { scope: 'read' });
 *         });
 *       }
 *     ));
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 *
 * @constructor
 * @param {Object} [options]
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('HTTPBearerStrategy requires a verify function'); }
  
  passport.Strategy.call(this);
  this.name = 'bearer';
  this._verify = verify;
  this._realm = options.realm || 'Users';
  if (options.scope) {
    this._scope = (Array.isArray(options.scope)) ? options.scope : [ options.scope ];
  }
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Bearer authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  var token, nTokens = 0;

  if (req.headers
      && req.headers.authorization
      && /^Bearer\s+\S+/i.test(req.headers.authorization)) {
    token = req.headers.authorization.split(/\s+/)[1];
    nTokens++;
  }

  if (req.body && req.body.access_token) {
      token = req.body.access_token;
      nTokens++;
  }

  if (req.query && req.query.access_token) {
      token = req.query.access_token;
      nTokens++;
  }

  switch (nTokens) {
    case 0:
      return this.fail(this._challenge(
          'invalid_request',
          'Clients MUST provide one of the following methods to transmit the access_token: '
          + 'an Authorization header with the Bearer scheme, '
          + 'a request body with an access_token field, '
          + 'or a query string with an access_token parameter.'
      ), 400);
    case 1:
      break;
    default:
      return this.fail(this._challenge(
          'invalid_request',
          'Clients MUST NOT use more than one method to transmit the access_token in each request.'
      ), 400);
  }

  var verified = {
    error: this.error.bind(this),
    success: this.success.bind(this),
    invalidToken: function(desc, uri) {
      this.fail(this.challenge('invalid_token', desc, uri), 401);
    },
    insufficientScope: function(desc, uri) {
      this.fail(this.challenge('insufficient_scope', desc, uri), 403);
    },
    fail: this.fail.bind(this),
    challenge: this._challenge.bind(this),
  };

  if (this._passReqToCallback) {
    this._verify(req, token, verified);
  } else {
    this._verify(token, verified);
  }
};

/**
 * Build authentication challenge.
 *
 * @api private
 */
Strategy.prototype._challenge = function(code, desc, uri) {
  var challenge = 'Bearer realm="' + this._realm + '"';
  if (this._scope) {
    challenge += ', scope="' + this._scope.join(' ') + '"';
  }
  if (code) {
    challenge += ', error="' + code + '"';
  }
  if (desc && desc.length) {
    challenge += ', error_description="' + desc + '"';
  }
  if (uri && uri.length) {
    challenge += ', error_uri="' + uri + '"';
  }
  
  return challenge;
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
