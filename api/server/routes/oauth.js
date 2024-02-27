// file deepcode ignore NoRateLimitingForLogin: Rate limiting is handled by the `loginLimiter` middleware

const passport = require('passport');
const express = require('express');
const router = express.Router();
const { setAuthTokens } = require('~/server/services/AuthService');
const { loginLimiter, checkBan } = require('~/server/middleware');
const { logger } = require('~/config');
const { generators } = require('openid-client');

const domains = {
  client: process.env.DOMAIN_CLIENT,
  server: process.env.DOMAIN_SERVER,
};

router.use(loginLimiter);

const oauthHandler = async (req, res) => {
  try {
    await checkBan(req, res);
    if (req.banned) {
      return;
    }

    const { token, refreshToken } = await setAuthTokens(req.user._id, res);

    const alternativeRedirect = readRedirectFromState(req);
    if (alternativeRedirect) {
      res.redirect(alternativeRedirect + '?token=' + token + '&refreshToken=' + refreshToken);
    } else {
      res.redirect(domains.client);
    }
  } catch (err) {
    logger.error('Error in setting authentication tokens:', err);
  }
};

const generateState = (req) => {
  let state;
  if (req.query.redirect) {
    const value = {
      redirect: req.query.redirect,
    };
    state = btoa(JSON.stringify(value));
  } else {
    state = generators.state();
  }
  return state;
};

const readRedirectFromState = (req) => {
  if (req.query.state) {
    try {
      const value = JSON.parse(atob(req.query.state));
      if (value) {
        return value.redirect;
      }
    } catch {
      return undefined;
    }
  }
  return undefined;
};

/**
 * Google Routes
 */
router.get('/google', (req, res, next) => {
  passport.authenticate('google', {
    scope: ['openid', 'profile', 'email'],
    session: false,
    state: generateState(req),
  })(req, res, next);
});

router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${domains.client}/login`,
    failureMessage: true,
    session: false,
    scope: ['openid', 'profile', 'email'],
  }),
  oauthHandler,
);

router.get('/facebook', (req, res, next) => {
  passport.authenticate('facebook', {
    scope: ['public_profile'],
    profileFields: ['id', 'email', 'name'],
    session: false,
    state: generateState(req),
  })(req, res, next);
});

router.get(
  '/facebook/callback',
  passport.authenticate('facebook', {
    failureRedirect: `${domains.client}/login`,
    failureMessage: true,
    session: false,
    scope: ['public_profile'],
    profileFields: ['id', 'email', 'name'],
  }),
  oauthHandler,
);

router.get('/openid', (req, res, next) => {
  passport.authenticate('openid', {
    session: false,
    state: generateState(req),
  })(req, res, next);
});

router.get(
  '/openid/callback',
  passport.authenticate('openid', {
    failureRedirect: `${domains.client}/login`,
    failureMessage: true,
    session: false,
  }),
  oauthHandler,
);

router.get('/github', (req, res, next) => {
  passport.authenticate('github', {
    scope: ['user:email', 'read:user'],
    session: false,
    state: generateState(req),
  })(req, res, next);
});

router.get(
  '/github/callback',
  passport.authenticate('github', {
    failureRedirect: `${domains.client}/login`,
    failureMessage: true,
    session: false,
    scope: ['user:email', 'read:user'],
  }),
  oauthHandler,
);
router.get('/discord', (req, res, next) => {
  passport.authenticate('discord', {
    scope: ['identify', 'email'],
    session: false,
    state: generateState(req),
  })(req, res, next);
});

router.get(
  '/discord/callback',
  passport.authenticate('discord', {
    failureRedirect: `${domains.client}/login`,
    failureMessage: true,
    session: false,
    scope: ['identify', 'email'],
  }),
  oauthHandler,
);

module.exports = router;
