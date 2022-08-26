var chai = require('chai');
var Strategy = require('../lib/strategy');

var challenges = {
  invalid_request: {
    zeroTokens:
      'Bearer realm="Users", error="invalid_request", error_description="'
      +   'Clients MUST provide one of the following methods to transmit the access_token: '
      +     'an Authorization header with the Bearer scheme, '
      +     'a request body with an access_token field, '
      +     'or a query string with an access_token parameter.'
      + '"',
    manyTokens: 
      'Bearer realm="Users", error="invalid_request", error_description="'
      +   'Clients MUST NOT use more than one method to transmit the access_token in each request.'
      + '"',
  },
}


describe('Strategy', function() {
  
  var strategy = new Strategy(function(token, cb) {
    throw new Error('verify function should not be called');
  });
  
  
  it('should be named bearer', function() {
    expect(strategy.name).to.equal('bearer');
  });
  
  it('should authenticate request with bearer scheme', function(done) {
    var strategy = new Strategy(function(token, cb) {
      return cb.success({ id: '248289761001' });
    });
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.be.undefined;
        done();
      })
      .authenticate();
  }); // should authenticate request with bearer scheme
  
  it('should authenticate request with case-insensitive bearer scheme', function(done) {
    var strategy = new Strategy(function(token, cb) {
      return cb.success({ id: '248289761001' });
    });
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'bearer mF_9.B5f-4.1JqM';
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.be.undefined;
        done();
      })
      .authenticate();
  }); // should authenticate request with case-insensitive bearer scheme
  
  it('should authenticate request with token in form-encoded body parameter', function(done) {
    var strategy = new Strategy(function(token, cb) {
      return cb.success({ id: '248289761001' });
    });
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.body = {};
        req.body.access_token = 'mF_9.B5f-4.1JqM';
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.be.undefined;
        done();
      })
      .authenticate();
  }); // should authenticate request with token in form-encoded body parameter
  
  it('should authenticate request with token in URI query parameter', function(done) {
    var strategy = new Strategy(function(token, cb) {
      return cb.success({ id: '248289761001' });
    });
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.query = {};
        req.query.access_token = 'mF_9.B5f-4.1JqM';
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.be.undefined;
        done();
      })
      .authenticate();
  }); // should authenticate request with token in URI query parameter
  
  it('should challenge request with realm', function(done) {
    var strategy = new Strategy({ realm: 'example' }, function(token, cb) {
      throw new Error('verify function should not be called');
    });
    
    chai.passport.use(strategy)
      .fail(function(challenge, status) {
        expect(challenge).to.match(/^Bearer realm="example"/);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should challenge request with scope as array', function(done) {
    var strategy = new Strategy({ scope: ['profile', 'email']  }, function(token, cb) {
      throw new Error('verify function should not be called');
    });
    
    chai.passport.use(strategy)
      .fail(function(challenge, status) {
        expect(challenge).to.match(/^Bearer realm="Users", scope="profile email"/);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should challenge request with scope as string', function(done) {
    var strategy = new Strategy({ scope: 'profile' }, function(token, cb) {
      throw new Error('verify function should not be called');
    });
    
    chai.passport.use(strategy)
      .fail(function(challenge, status) {
        expect(challenge).to.match(/^Bearer realm="Users", scope="profile"/);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should challenge request without credentials', function(done) {
    chai.passport.use(strategy)
      .fail(function(challenge, status) {
        expect(challenge).to.equal(challenges.invalid_request.zeroTokens);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should challenge request with non-bearer scheme', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal(challenges.invalid_request.zeroTokens);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should challenge request with scheme name differing by suffix', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'Bearer2 mF_9.B5f-4.1JqM';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal(challenges.invalid_request.zeroTokens);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should challenge request with scheme name differing by prefix', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'XBearer mF_9.B5f-4.1JqM';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal(challenges.invalid_request.zeroTokens);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should refuse request with with bearer scheme that lacks token', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'Bearer';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal(challenges.invalid_request.zeroTokens);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should refuse request with token transmitted in both header field and form-encoded body parameter', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        req.body = {};
        req.body.access_token = 'mF_9.B5f-4.1JqM';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal(challenges.invalid_request.manyTokens);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should refuse request with token transmitted in both header field and URI query parameter', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        req.query = {};
        req.query.access_token = 'mF_9.B5f-4.1JqM';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal(challenges.invalid_request.manyTokens);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should refuse request with token transmitted in both form-encoded body parameter and URI query parameter', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.body = {};
        req.body.access_token = 'mF_9.B5f-4.1JqM';
        req.query = {};
        req.query.access_token = 'mF_9.B5f-4.1JqM';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal(challenges.invalid_request.manyTokens);
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  it('should throw if constructed without a verify function', function() {
    expect(function() {
      new Strategy();
    }).to.throw(TypeError, 'HTTPBearerStrategy requires a verify function');
  });
  
});
