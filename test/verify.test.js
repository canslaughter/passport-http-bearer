var chai = require('chai');
var Strategy = require('../lib/strategy');


describe('verify function', function() {
  
  describe('that authenticates', function() {
  
    it('should authenticate request', function(done) {
      var strategy = new Strategy(function(token, cb) {
        expect(token).to.equal('mF_9.B5f-4.1JqM');
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
    }); // should authenticate request
  
    it('should authenticate request with additional info', function(done) {
      var strategy = new Strategy(function(token, cb) {
        expect(token).to.equal('mF_9.B5f-4.1JqM');
        return cb.success({ id: '248289761001' }, { scope: [ 'profile', 'email' ] });
      });
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        })
        .success(function(user, info) {
          expect(user).to.deep.equal({ id: '248289761001' });
          expect(info).to.deep.equal({ scope: [ 'profile', 'email' ] });
          done();
        })
        .authenticate();
    }); // should authenticate request with additional info
    
    it('should accept request argument and authenticate request', function(done) {
      var strategy = new Strategy({ passReqToCallback: true }, function(req, token, cb) {
        expect(req.url).to.equal('/');
        expect(token).to.equal('mF_9.B5f-4.1JqM');
        return cb.success({ id: '248289761001' }, { scope: [ 'profile', 'email' ] });
      });
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        })
        .success(function(user, info) {
          expect(user).to.deep.equal({ id: '248289761001' });
          expect(info).to.deep.equal({ scope: [ 'profile', 'email' ] });
          done();
        })
        .authenticate();
    }); // should accept request argument and authenticate request
  
  }); // that authenticates
  
  describe('that does not authenticate', function() {
    
    it('should challenge request with invalid_token', function(done) {
      var strategy = new Strategy(function(token, cb) {
        return cb.invalidToken('challenge error description', 'challenge error uri');
      });
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        })
        .fail(function(challenge, status) {
          expect(challenge).to.equal(
            'Bearer realm="Users", error="invalid_token", '
            + 'error_description="challenge error description", '
            + 'error_uri="challenge error uri"'
          );
          expect(status).to.equal(401);
          done();
        })
        .authenticate();
    }); // should challenge request with invalid_token
    
    it('should challenge request with insufficient_scope', function(done) {
      var strategy = new Strategy(function(token, cb) {
        return cb.insufficientScope('challenge error description', 'challenge error uri');
      });
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        })
        .fail(function(challenge, status) {
          expect(challenge).to.equal(
            'Bearer realm="Users", error="insufficient_scope", '
            + 'error_description="challenge error description", '
            + 'error_uri="challenge error uri"'
          );
          expect(status).to.equal(403);
          done();
        })
        .authenticate();
    }); // should challenge request with insufficient_scope
    
    it('should challenge request with custom challenge error code and http status', function(done) {
      var strategy = new Strategy(function(token, cb) {
        return cb.fail(cb.challenge('custom_code', 'challenge error description', 'challenge error uri'), 401);
      });
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        })
        .fail(function(challenge, status) {
          expect(challenge).to.equal(
            'Bearer realm="Users", error="custom_code", '
            + 'error_description="challenge error description", '
            + 'error_uri="challenge error uri"'
          );
          expect(status).to.equal(401);
          done();
        })
        .authenticate();
    }); // should challenge request with custom challenge error code and http status
    
  }); // that does not authenticate
  
  describe('that errors', function() {
    
    it('should error request', function(done) {
      var strategy = new Strategy(function(token, cb) {
        return cb.error(new Error('something went wrong'));
      });
      
      chai.passport.use(strategy)
        .request(function(req) {
          req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        })
        .error(function(err) {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('something went wrong');
          done();
        })
        .authenticate();
    }); // should error request
    
  }); // that errors
  
});
