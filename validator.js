// Token Validator - manojxshrestha CredStalker
// Validates critical tokens for security alerts in authorized environments

const TOKEN_VALIDATORS = {

  // Firebase API Key Validation
  FIREBASE: async (token) => {
    try {
      // Try to make a simple request to Firebase API
      const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${token}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ returnSecureToken: true })
      });

      const data = await response.json();

      // If it returns specific error for invalid API key
      if (data.error && data.error.message === 'API key not valid') {
        return { valid: false, status: 'Token invalid or expired' };
      }

      // If it returns any other response, the API key is valid
      if (response.status === 400 && data.error && data.error.message.includes('MISSING')) {
        return { valid: true, status: 'Token valid and active', severity: 'CRITICAL' };
      }

        return { valid: true, status: 'Token valid', severity: 'CRITICAL' };
    } catch (error) {
      return { valid: null, status: 'Error validating: ' + error.message };
    }
  },

  // GitHub Token Validation
  GITHUB: async (token) => {
    try {
      const response = await fetch('https://api.github.com/user', {
        headers: {
          'Authorization': `token ${token}`,
          'User-Agent': 'Security-Monitor'
        }
      });

      if (response.status === 200) {
        const data = await response.json();
        return {
          valid: true,
          status: `Token valid - User: ${data.login}`,
          severity: 'CRITICAL',
          metadata: { username: data.login, email: data.email }
        };
      } else if (response.status === 401) {
        return { valid: false, status: 'Token invalid or expired' };
      } else {
        return { valid: null, status: `HTTP Status: ${response.status}` };
      }
    } catch (error) {
      return { valid: null, status: 'Error validating: ' + error.message };
    }
  },

  // GitLab Token Validation
  GITLAB: async (token) => {
    try {
      const response = await fetch('https://gitlab.com/api/v4/user', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        const data = await response.json();
        return {
          valid: true,
          status: `Token valid - User: ${data.username}`,
          severity: 'CRITICAL',
          metadata: { username: data.username, email: data.email }
        };
      } else if (response.status === 401) {
        return { valid: false, status: 'Token invalid or expired' };
      } else {
        return { valid: null, status: `HTTP Status: ${response.status}` };
      }
    } catch (error) {
      return { valid: null, status: 'Error validating: ' + error.message };
    }
  },

  // Vercel Token Validation (Expanded for Bug Bounty)
  VERCEL: async (token) => {
    try {
      // Test /v2/user endpoint
      const userResponse = await fetch('https://api.vercel.com/v2/user', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (userResponse.status === 200) {
        const userData = await userResponse.json();

        // Test additional permissions
        const teamsResponse = await fetch('https://api.vercel.com/v2/teams', {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        const projectsResponse = await fetch('https://api.vercel.com/v9/projects', {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        const teams = teamsResponse.ok ? await teamsResponse.json() : null;
        const projects = projectsResponse.ok ? await projectsResponse.json() : null;

        return {
          valid: true,
          status: `VERCEL Token valid - User: ${userData.user.username || userData.user.email}`,
          severity: 'CRITICAL',
          metadata: {
            username: userData.user.username,
            email: userData.user.email,
            teams: teams?.teams?.length || 0,
            projects: projects?.projects?.length || 0,
            scope: 'Full API Access'
          }
        };
      } else if (userResponse.status === 403 || userResponse.status === 401) {
        return { valid: false, status: 'Token invalid or expired' };
      } else {
        return { valid: null, status: `HTTP Status: ${userResponse.status}` };
      }
    } catch (error) {
      return { valid: null, status: 'Error validating: ' + error.message };
    }
  },

  // Supabase Token Validation (Expanded - Bug Bounty)
  SUPABASE: async (token, projectUrl = null) => {
    try {
      // Supabase API keys are JWTs
      if (token.startsWith('eyJ') && token.includes('.')) {
        // Decode JWT
        try {
          const payload = JSON.parse(atob(token.split('.')[1]));
          const now = Math.floor(Date.now() / 1000);

          // Determine key type
          const role = payload.role || 'unknown';
          const isServiceRole = role === 'service_role';
          const isAnonKey = role === 'anon';

          // Check expiration
          if (payload.exp && payload.exp < now) {
            return { valid: false, status: 'Supabase JWT expired' };
          }

          // If we have project URL, test real access
          if (projectUrl || payload.iss) {
            const baseUrl = projectUrl || payload.iss;

            try {
              // Test REST endpoint
              const testResponse = await fetch(`${baseUrl}/rest/v1/`, {
                headers: {
                  'apikey': token,
                  'Authorization': `Bearer ${token}`
                }
              });

              // Test write permissions (only for service_role)
              let writeAccess = false;
              if (isServiceRole) {
                try {
                  const writeTest = await fetch(`${baseUrl}/rest/v1/rpc/`, {
                    method: 'POST',
                    headers: {
                      'apikey': token,
                      'Authorization': `Bearer ${token}`,
                      'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({})
                  });
                  writeAccess = writeTest.status !== 401 && writeTest.status !== 403;
                } catch (e) {
                  // Ignore error
                }
              }

              return {
                valid: true,
                status: `SUPABASE ${role.toUpperCase()} Key valid - Project: ${baseUrl}`,
                severity: isServiceRole ? 'CRITICAL' : 'HIGH',
                metadata: {
                  role: role,
                  projectUrl: baseUrl,
                  expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'never',
                  writeAccess: isServiceRole ? writeAccess : 'N/A',
                  issuer: payload.iss
                }
              };

            } catch (fetchError) {
              // Key is valid but we couldn't test access
              return {
                valid: true,
                status: `SUPABASE ${role.toUpperCase()} Key valid (correct JWT format)`,
                severity: isServiceRole ? 'CRITICAL' : 'HIGH',
                metadata: {
                  role: role,
                  expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'never',
                  note: 'Could not test real access'
                }
              };
            }
          }

          // Without URL, just validate JWT
          return {
            valid: true,
                status: `SUPABASE ${role.toUpperCase()} Key valid (JWT not expired)`,
            severity: isServiceRole ? 'CRITICAL' : 'HIGH',
            metadata: {
              role: role,
              expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'never',
              note: 'Project URL not provided - partial validation'
            }
          };

        } catch (decodeError) {
          return { valid: false, status: 'Invalid Supabase JWT format' };
        }
      }

      return { valid: null, status: 'Token does not appear to be a valid Supabase key' };
    } catch (error) {
      return { valid: null, status: 'Error validating: ' + error.message };
    }
  },

  // AWS Credentials Validation
  AWS: async (token) => {
    // AWS requires access key ID + secret, we cannot validate with just one
    return {
      valid: null,
      status: 'AWS validation requires Access Key ID + Secret Access Key',
      severity: 'CRITICAL'
    };
  },

  // Slack Token Validation
  SLACK: async (token) => {
    try {
      const response = await fetch('https://slack.com/api/auth.test', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });

      const data = await response.json();

      if (data.ok) {
        return {
          valid: true,
          status: `Token valid - Team: ${data.team}`,
          severity: 'HIGH',
          metadata: { user: data.user, team: data.team }
        };
      } else {
        return { valid: false, status: data.error || 'Invalid token' };
      }
    } catch (error) {
      return { valid: null, status: 'Error validating: ' + error.message };
    }
  },

  // Stripe Key Validation
  STRIPE: async (token) => {
    try {
      // Try to list customers (read-only operation)
      const response = await fetch('https://api.stripe.com/v1/customers?limit=1', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return {
          valid: true,
          status: 'Stripe token valid (account access)',
          severity: 'CRITICAL'
        };
      } else if (response.status === 401) {
        return { valid: false, status: 'Token invalid or expired' };
      } else {
        return { valid: null, status: `HTTP Status: ${response.status}` };
      }
    } catch (error) {
      return { valid: null, status: 'Error validating: ' + error.message };
    }
  },

  // Google API Key Validation
  GOOGLE: async (token) => {
    try {
      // Try a public Google API
      const response = await fetch(`https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=${token}&maxResults=1`);

      const data = await response.json();

      if (response.status === 200) {
        return {
          valid: true,
          status: 'Google API Key valid',
          severity: 'HIGH'
        };
      } else if (data.error && data.error.message.includes('API key not valid')) {
        return { valid: false, status: 'Invalid API Key' };
      } else if (data.error && data.error.message.includes('has not been used')) {
        return {
          valid: true,
          status: 'API Key valid (has not been used yet)',
          severity: 'HIGH'
        };
      } else {
        return { valid: null, status: data.error?.message || 'Error validating' };
      }
    } catch (error) {
      return { valid: null, status: 'Error validating: ' + error.message };
    }
  },

  // JWT Token Validation (generic)
  JWT: async (token) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return { valid: false, status: 'Invalid JWT format' };
      }

      const payload = JSON.parse(atob(parts[1]));
      const now = Math.floor(Date.now() / 1000);

      if (payload.exp) {
        if (payload.exp > now) {
          return {
            valid: true,
            status: 'JWT valid and not expired',
            severity: 'MEDIUM',
            metadata: {
              expires: new Date(payload.exp * 1000).toISOString(),
              issuer: payload.iss,
              subject: payload.sub
            }
          };
        } else {
          return { valid: false, status: 'JWT expired' };
        }
      } else {
        return {
          valid: null,
          status: 'JWT without expiration date (verify manually)',
          severity: 'MEDIUM'
        };
      }
    } catch (error) {
      return { valid: false, status: 'Error decoding JWT: ' + error.message };
    }
  }
};

// Check if value seems to be a false positive before validating
function isLikelyFalsePositive(value) {
  // Check if it's just common words separated by underscore
  if (/^[a-z]+(_[a-z]+){2,}$/.test(value)) {
    return true;
  }

  // If it has no uppercase or numbers, it's probably a false positive
  const hasUpperCase = /[A-Z]/.test(value);
  const hasNumbers = /[0-9]/.test(value);

  if (!hasUpperCase && !hasNumbers && value.length < 40) {
    return true;
  }

  return false;
}

// Main validation function
async function validateToken(type, value) {
  console.log(`🔍 Validating token of type: ${type}`);

  // Pre-validation: detect false positives before making requests
  if (isLikelyFalsePositive(value)) {
    console.log(`⚠️ Token seems to be a false positive: ${value}`);
    return {
      valid: false,
      status: 'Likely false positive (variable name or feature flag)',
      severity: 'LOW'
    };
  }

  // Map types to validators
  const validatorMap = {
    'FIREBASE': 'FIREBASE',
    'GITHUB': 'GITHUB',
    'GITLAB': 'GITLAB',
    'VERCEL': 'VERCEL',
    'SUPABASE': 'SUPABASE',
    'AWS': 'AWS',
    'SLACK': 'SLACK',
    'STRIPE': 'STRIPE',
    'GOOGLE': 'GOOGLE',
    'JWT': 'JWT',
    'API_KEY': null, // Generic, we don't validate
    'TOKEN': null,
    'SECRET': null,
    'PASSWORD': null,
    'PRIVATE_KEY': null
  };

  const validatorType = validatorMap[type];

  if (!validatorType || !TOKEN_VALIDATORS[validatorType]) {
    return {
      valid: null,
      status: 'Validation not available for this type',
      severity: 'MEDIUM'
    };
  }

  try {
    const result = await TOKEN_VALIDATORS[validatorType](value);
    console.log(`✅ Validation result:`, result);
    return result;
  } catch (error) {
    console.error(`❌ Error validating token:`, error);
    return {
      valid: null,
      status: 'Error during validation: ' + error.message
    };
  }
}

// Validate multiple tokens in batch
async function validateTokensBatch(tokens) {
  const results = [];

  for (const token of tokens) {
    const validation = await validateToken(token.type, token.value);
    results.push({
      ...token,
      validation
    });

    // Small delay between requests to avoid rate limiting
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  return results;
}

// Export for use in other scripts (ES6 module)
export { validateToken, validateTokensBatch };
