const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

/**
 * SSO Authentication Service
 * Handles OAuth 2.0 flows for Bike Index and Go High Level
 */

class SSOService {
  constructor() {
    this.bikeIndexOAuthConfig = {
      clientId: process.env.BIKE_INDEX_OAUTH_CLIENT_ID,
      clientSecret: process.env.BIKE_INDEX_OAUTH_CLIENT_SECRET,
      redirectUri: process.env.BIKE_INDEX_OAUTH_REDIRECT_URI || 'http://localhost:3000/auth/bike-index/callback',
      authorizationUrl: 'https://www.bikeindex.org/oauth/authorize',
      tokenUrl: 'https://www.bikeindex.org/oauth/token',
    };

    this.ghlOAuthConfig = {
      clientId: process.env.GHL_OAUTH_CLIENT_ID,
      clientSecret: process.env.GHL_OAUTH_CLIENT_SECRET,
      redirectUri: process.env.GHL_OAUTH_REDIRECT_URI || 'http://localhost:3000/auth/ghl/callback',
      authorizationUrl: 'https://app.gohighlevel.com/oauth/authorize',
      tokenUrl: 'https://rest.gohighlevel.com/oauth/token',
    };

    this.jwtSecret = process.env.JWT_SECRET || 'your-super-secret-jwt-key';
    this.tokenExpiry = process.env.TOKEN_EXPIRY || '24h';
    this.refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || '30d';
  }

  /**
   * Generate OAuth authorization URL for Bike Index
   */
  getBikeIndexAuthUrl(state) {
    const params = new URLSearchParams({
      client_id: this.bikeIndexOAuthConfig.clientId,
      response_type: 'code',
      redirect_uri: this.bikeIndexOAuthConfig.redirectUri,
      scope: 'read write',
      state: state || crypto.randomBytes(16).toString('hex'),
    });

    return `${this.bikeIndexOAuthConfig.authorizationUrl}?${params.toString()}`;
  }

  /**
   * Generate OAuth authorization URL for Go High Level
   */
  getGHLAuthUrl(state) {
    const params = new URLSearchParams({
      client_id: this.ghlOAuthConfig.clientId,
      response_type: 'code',
      redirect_uri: this.ghlOAuthConfig.redirectUri,
      scope: 'contacts.write contacts.read cases.write cases.read tasks.write tasks.read tags.read',
      state: state || crypto.randomBytes(16).toString('hex'),
    });

    return `${this.ghlOAuthConfig.authorizationUrl}?${params.toString()}`;
  }

  /**
   * Exchange authorization code for Bike Index access token
   */
  async exchangeBikeIndexCode(code) {
    try {
      const response = await axios.post(this.bikeIndexOAuthConfig.tokenUrl, {
        grant_type: 'authorization_code',
        code,
        client_id: this.bikeIndexOAuthConfig.clientId,
        client_secret: this.bikeIndexOAuthConfig.clientSecret,
        redirect_uri: this.bikeIndexOAuthConfig.redirectUri,
      });

      return {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        expiresIn: response.data.expires_in,
        tokenType: response.data.token_type,
      };
    } catch (error) {
      console.error('Error exchanging Bike Index code:', error.response?.data || error.message);
      throw new Error('Failed to exchange Bike Index authorization code');
    }
  }

  /**
   * Exchange authorization code for Go High Level access token
   */
  async exchangeGHLCode(code) {
    try {
      const response = await axios.post(this.ghlOAuthConfig.tokenUrl, {
        grant_type: 'authorization_code',
        code,
        client_id: this.ghlOAuthConfig.clientId,
        client_secret: this.ghlOAuthConfig.clientSecret,
        redirect_uri: this.ghlOAuthConfig.redirectUri,
      });

      return {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        expiresIn: response.data.expires_in,
        tokenType: response.data.token_type,
        locationId: response.data.location_id,
      };
    } catch (error) {
      console.error('Error exchanging GHL code:', error.response?.data || error.message);
      throw new Error('Failed to exchange Go High Level authorization code');
    }
  }

  /**
   * Refresh Bike Index access token
   */
  async refreshBikeIndexToken(refreshToken) {
    try {
      const response = await axios.post(this.bikeIndexOAuthConfig.tokenUrl, {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.bikeIndexOAuthConfig.clientId,
        client_secret: this.bikeIndexOAuthConfig.clientSecret,
      });

      return {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        expiresIn: response.data.expires_in,
      };
    } catch (error) {
      console.error('Error refreshing Bike Index token:', error.message);
      throw new Error('Failed to refresh Bike Index token');
    }
  }

  /**
   * Refresh Go High Level access token
   */
  async refreshGHLToken(refreshToken) {
    try {
      const response = await axios.post(this.ghlOAuthConfig.tokenUrl, {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.ghlOAuthConfig.clientId,
        client_secret: this.ghlOAuthConfig.clientSecret,
      });

      return {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        expiresIn: response.data.expires_in,
      };
    } catch (error) {
      console.error('Error refreshing GHL token:', error.message);
      throw new Error('Failed to refresh Go High Level token');
    }
  }

  /**
   * Get user info from Bike Index
   */
  async getBikeIndexUserInfo(accessToken) {
    try {
      const response = await axios.get('https://www.bikeindex.org/api/v3/me', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      });

      return response.data;
    } catch (error) {
      console.error('Error fetching Bike Index user info:', error.message);
      throw new Error('Failed to fetch Bike Index user information');
    }
  }

  /**
   * Get user info from Go High Level
   */
  async getGHLUserInfo(accessToken, locationId) {
    try {
      const response = await axios.get(
        `https://rest.gohighlevel.com/v1/locations/${locationId}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
        }
      );

      return response.data;
    } catch (error) {
      console.error('Error fetching GHL user info:', error.message);
      throw new Error('Failed to fetch Go High Level user information');
    }
  }

  /**
   * Generate JWT token for authenticated user
   */
  generateJWT(userData) {
    const payload = {
      userId: userData.id,
      email: userData.email,
      name: userData.name,
      bikeIndexId: userData.bikeIndexId,
      ghlLocationId: userData.ghlLocationId,
      role: userData.role || 'user',
      iat: Math.floor(Date.now() / 1000),
    };

    const token = jwt.sign(payload, this.jwtSecret, {
      expiresIn: this.tokenExpiry,
    });

    return token;
  }

  /**
   * Verify JWT token
   */
  verifyJWT(token) {
    try {
      return jwt.verify(token, this.jwtSecret);
    } catch (error) {
      console.error('JWT verification failed:', error.message);
      return null;
    }
  }

  /**
   * Generate refresh token
   */
  generateRefreshToken(userId) {
    const payload = {
      userId,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000),
    };

    return jwt.sign(payload, this.jwtSecret, {
      expiresIn: this.refreshTokenExpiry,
    });
  }

  /**
   * Create unified user session
   */
  async createUserSession(bikeIndexData, ghlData) {
    const userData = {
      id: crypto.randomBytes(8).toString('hex'),
      email: bikeIndexData.email || ghlData.email,
      name: bikeIndexData.name || ghlData.name,
      bikeIndexId: bikeIndexData.id,
      ghlLocationId: ghlData.location_id || ghlData.id,
      bikeIndexTokens: bikeIndexData.tokens,
      ghlTokens: ghlData.tokens,
      createdAt: new Date(),
      lastLogin: new Date(),
    };

    return userData;
  }

  /**
   * Validate user permissions
   */
  validateUserPermissions(token, requiredScope) {
    const decoded = this.verifyJWT(token);
    if (!decoded) return false;

    const userScopes = decoded.scopes || [];
    return requiredScope.every(scope => userScopes.includes(scope));
  }

  /**
   * Revoke user tokens (logout)
   */
  async revokeTokens(bikeIndexToken, ghlToken) {
    const results = {
      bikeIndex: false,
      ghl: false,
    };

    try {
      // Revoke Bike Index token
      await axios.post('https://www.bikeindex.org/oauth/revoke', {
        token: bikeIndexToken,
        client_id: this.bikeIndexOAuthConfig.clientId,
        client_secret: this.bikeIndexOAuthConfig.clientSecret,
      });
      results.bikeIndex = true;
    } catch (error) {
      console.error('Error revoking Bike Index token:', error.message);
    }

    try {
      // Revoke GHL token
      await axios.post('https://rest.gohighlevel.com/oauth/revoke', {
        token: ghlToken,
        client_id: this.ghlOAuthConfig.clientId,
        client_secret: this.ghlOAuthConfig.clientSecret,
      });
      results.ghl = true;
    } catch (error) {
      console.error('Error revoking GHL token:', error.message);
    }

    return results;
  }
}

module.exports = new SSOService();
