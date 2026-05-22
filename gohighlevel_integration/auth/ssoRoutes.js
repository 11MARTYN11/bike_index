const express = require('express');
const router = express.Router();
const ssoService = require('./sso');
const sessionManager = require('./sessionManager');
const crypto = require('crypto');
require('dotenv').config();

// Helper function to get redirect URIs from env
const getRedirectUris = (platform) => {
  const uris = [];
  let i = 1;
  let key = `${platform}_OAUTH_REDIRECT_URI_${i}`;

  while (process.env[key]) {
    uris.push(process.env[key]);
    i++;
    key = `${platform}_OAUTH_REDIRECT_URI_${i}`;
  }

  return uris;
};

const bikeIndexRedirectUris = getRedirectUris('BIKE_INDEX');
const ghlRedirectUris = getRedirectUris('GHL');

// Store state temporarily (in production, use Redis or database)
const stateStore = new Map();

// ==========================================
// GET AVAILABLE REDIRECT URIs
// ==========================================
router.get('/redirect-uris', (req, res) => {
  res.json({
    bikeIndex: bikeIndexRedirectUris,
    ghl: ghlRedirectUris,
  });
});

// ==========================================
// BIKE INDEX OAUTH FLOW
// ==========================================

/**
 * Initiate Bike Index OAuth login
 * GET /auth/bike-index
 * Query params: redirect_uri (optional)
 */
router.get('/bike-index', (req, res) => {
  try {
    const requestedRedirectUri = req.query.redirect_uri;

    // Validate redirect URI if provided
    if (requestedRedirectUri && !bikeIndexRedirectUris.includes(requestedRedirectUri)) {
      return res.status(400).json({
        error: 'invalid_redirect_uri',
        message: `Redirect URI not allowed. Use one of: ${bikeIndexRedirectUris.join(', ')}`,
      });
    }

    const state = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    stateStore.set(state, {
      platform: 'bikeIndex',
      expiresAt,
      redirectUri: requestedRedirectUri,
    });

    const authUrl = ssoService.getBikeIndexAuthUrl(state);
    res.redirect(authUrl);
  } catch (error) {
    console.error('Error initiating Bike Index OAuth:', error);
    res.status(500).json({ error: 'oauth_initiation_failed' });
  }
});

/**
 * Bike Index OAuth callback
 * GET /auth/bike-index/callback?code=...&state=...
 */
router.get('/bike-index/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).json({
        error,
        message: 'Bike Index OAuth authorization denied',
      });
    }

    // Validate state
    const stateData = stateStore.get(state);
    if (!stateData || stateData.platform !== 'bikeIndex') {
      return res.status(400).json({ error: 'invalid_state' });
    }

    if (stateData.expiresAt < Date.now()) {
      stateStore.delete(state);
      return res.status(400).json({ error: 'state_expired' });
    }

    stateStore.delete(state);

    // Exchange code for token
    const tokenData = await ssoService.exchangeBikeIndexCode(code);

    // Get user info
    const userInfo = await ssoService.getBikeIndexUserInfo(tokenData.accessToken);

    // Store in session
    req.session = {
      bikeIndexData: {
        ...userInfo,
        tokens: tokenData,
      },
    };

    // For out-of-band flow, show token to user
    if (stateData.redirectUri === 'urn:ietf:wg:oauth:2.0:oob') {
      return res.json({
        message: 'Authorization successful',
        accessToken: tokenData.accessToken,
        refreshToken: tokenData.refreshToken,
        expiresIn: tokenData.expiresIn,
      });
    }

    // Redirect to GHL OAuth flow
    res.redirect('/auth/ghl');
  } catch (error) {
    console.error('Error in Bike Index callback:', error);
    res.status(500).json({ error: 'callback_processing_failed' });
  }
});

// ==========================================
// GO HIGH LEVEL OAUTH FLOW
// ==========================================

/**
 * Initiate Go High Level OAuth login
 * GET /auth/ghl
 * Query params: redirect_uri (optional)
 */
router.get('/ghl', (req, res) => {
  try {
    const requestedRedirectUri = req.query.redirect_uri;

    // Validate redirect URI if provided
    if (requestedRedirectUri && !ghlRedirectUris.includes(requestedRedirectUri)) {
      return res.status(400).json({
        error: 'invalid_redirect_uri',
        message: `Redirect URI not allowed. Use one of: ${ghlRedirectUris.join(', ')}`,
      });
    }

    const state = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    stateStore.set(state, {
      platform: 'ghl',
      expiresAt,
      redirectUri: requestedRedirectUri,
    });

    const authUrl = ssoService.getGHLAuthUrl(state);
    res.redirect(authUrl);
  } catch (error) {
    console.error('Error initiating GHL OAuth:', error);
    res.status(500).json({ error: 'oauth_initiation_failed' });
  }
});

/**
 * Go High Level OAuth callback
 * GET /auth/ghl/callback?code=...&state=...
 */
router.get('/ghl/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).json({
        error,
        message: 'Go High Level OAuth authorization denied',
      });
    }

    // Validate state
    const stateData = stateStore.get(state);
    if (!stateData || stateData.platform !== 'ghl') {
      return res.status(400).json({ error: 'invalid_state' });
    }

    if (stateData.expiresAt < Date.now()) {
      stateStore.delete(state);
      return res.status(400).json({ error: 'state_expired' });
    }

    stateStore.delete(state);

    // Exchange code for token
    const tokenData = await ssoService.exchangeGHLCode(code);

    // Get user info
    const userInfo = await ssoService.getGHLUserInfo(
      tokenData.accessToken,
      tokenData.locationId
    );

    // For out-of-band flow, show token to user
    if (stateData.redirectUri === 'urn:ietf:wg:oauth:2.0:oob') {
      return res.json({
        message: 'Authorization successful',
        accessToken: tokenData.accessToken,
        refreshToken: tokenData.refreshToken,
        expiresIn: tokenData.expiresIn,
        locationId: tokenData.locationId,
      });
    }

    // Create unified session
    const bikeIndexData = req.session?.bikeIndexData || {};
    const userData = await ssoService.createUserSession(
      bikeIndexData,
      { ...userInfo, tokens: tokenData, location_id: tokenData.locationId }
    );

    // Generate JWT
    const jwtToken = ssoService.generateJWT(userData);

    // Save session
    sessionManager.createSession(userData);

    // Set JWT in cookie
    res.cookie('jwt', jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    res.redirect('/dashboard?session=created');
  } catch (error) {
    console.error('Error in GHL callback:', error);
    res.status(500).json({ error: 'callback_processing_failed' });
  }
});

// ==========================================
// TOKEN REFRESH
// ==========================================

/**
 * Refresh JWT token
 * POST /auth/refresh
 */
router.post('/refresh', (req, res) => {
  try {
    const token = req.cookies.jwt || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'no_token_provided' });
    }

    const decoded = ssoService.verifyJWT(token);
    if (!decoded) {
      return res.status(401).json({ error: 'invalid_token' });
    }

    // Generate new token
    const newToken = ssoService.generateJWT({
      id: decoded.userId,
      email: decoded.email,
      name: decoded.name,
      bikeIndexId: decoded.bikeIndexId,
      ghlLocationId: decoded.ghlLocationId,
      role: decoded.role,
    });

    res.cookie('jwt', newToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({ message: 'Token refreshed', token: newToken });
  } catch (error) {
    console.error('Error refreshing token:', error);
    res.status(500).json({ error: 'token_refresh_failed' });
  }
});

// ==========================================
// USER INFO
// ==========================================

/**
 * Get current user info
 * GET /auth/user
 */
router.get('/user', (req, res) => {
  try {
    const token = req.cookies.jwt || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'no_token_provided' });
    }

    const decoded = ssoService.verifyJWT(token);
    if (!decoded) {
      return res.status(401).json({ error: 'invalid_token' });
    }

    res.json({
      id: decoded.userId,
      email: decoded.email,
      name: decoded.name,
      bikeIndexId: decoded.bikeIndexId,
      ghlLocationId: decoded.ghlLocationId,
      role: decoded.role,
    });
  } catch (error) {
    console.error('Error fetching user info:', error);
    res.status(500).json({ error: 'user_fetch_failed' });
  }
});

// ==========================================
// LOGOUT
// ==========================================

/**
 * Logout user
 * POST /auth/logout
 */
router.post('/logout', async (req, res) => {
  try {
    const token = req.cookies.jwt || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'no_token_provided' });
    }

    const decoded = ssoService.verifyJWT(token);
    if (!decoded) {
      return res.status(401).json({ error: 'invalid_token' });
    }

    // Get session and revoke tokens
    const session = sessionManager.getSession(decoded.userId);
    if (session) {
      await ssoService.revokeTokens(
        session.bikeIndexTokens?.accessToken,
        session.ghlTokens?.accessToken
      );

      sessionManager.deleteSession(decoded.userId);
    }

    // Clear JWT cookie
    res.clearCookie('jwt');

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Error during logout:', error);
    res.status(500).json({ error: 'logout_failed' });
  }
});

// ==========================================
// VALIDATE AUTHENTICATION
// ==========================================

/**
 * Validate if user is authenticated
 * GET /auth/validate
 */
router.get('/validate', (req, res) => {
  try {
    const token = req.cookies.jwt || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ authenticated: false });
    }

    const decoded = ssoService.verifyJWT(token);
    if (!decoded) {
      return res.status(401).json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      user: {
        id: decoded.userId,
        email: decoded.email,
        name: decoded.name,
        role: decoded.role,
      },
    });
  } catch (error) {
    console.error('Error validating authentication:', error);
    res.status(500).json({ authenticated: false, error: 'validation_failed' });
  }
});

module.exports = router;
