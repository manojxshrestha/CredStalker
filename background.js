// Background Service Worker - manojxshrestha CredStalker
// Manages notifications, webhooks, and storage

console.log('🔍 CredStalker - Background Service Worker started');

// Global state of Deep Scan
let deepScanState = {
  isRunning: false,
  tabId: null,
  startTime: null,
  progress: {
    pagesVisited: 0,
    scriptsAnalyzed: 0,
    tokensFound: 0
  },
  results: null
};

// Initialize default settings
chrome.runtime.onInstalled.addListener(async () => {
  const defaultSettings = {
    autoScanEnabled: false,
    notificationsEnabled: true,
    discordWebhookEnabled: false,
    discordWebhookUrl: '',
    saveHistory: true,
    scanDelay: 5000, // 5 seconds after loading (increased to not freeze the site)
    minTokenLength: 15,

    // Domain filter
    skipSocialMediaScan: true, // Skip social media by default

    // Proxy settings
    proxyEnabled: false,
    proxyHost: '127.0.0.1',
    proxyPort: 8080
  };

  // Check if configuration already exists
  const { settings } = await chrome.storage.local.get('settings');
  if (!settings) {
    await chrome.storage.local.set({ settings: defaultSettings });
    console.log('⚙️ Default settings created');
  }

  // Initialize history if it doesn't exist
  const { history } = await chrome.storage.local.get('history');
  if (!history) {
    await chrome.storage.local.set({ history: [] });
    console.log('📚 History initialized');
  }
});

// Unified listener for all messages
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Messages from content script
  if (request.action === 'tokensFound') {
    if (sender.tab) {
      handleTokensFound(request.data, sender.tab);
    } else {
      console.warn('⚠️ tokensFound received without associated tab');
    }
    sendResponse({ status: 'received' });
  } else if (request.action === 'manualScan') {
    if (sender.tab) {
      handleManualScan(request.data, sender.tab);
    } else {
      console.warn('⚠️ manualScan received without associated tab');
    }
    sendResponse({ status: 'received' });
  } else if (request.action === 'deepScanStarted') {
    // Deep scan started
    deepScanState.isRunning = true;
    deepScanState.tabId = sender.tab?.id || null;
    deepScanState.startTime = Date.now();
    deepScanState.progress = request.progress || { pagesVisited: 0, scriptsAnalyzed: 0, tokensFound: 0 };
    console.log('🕷️ Deep Scan started and registered in background');
    sendResponse({ status: 'registered' });
  } else if (request.action === 'deepScanProgress') {
    // Update deep scan progress
    if (deepScanState.isRunning) {
      deepScanState.progress = request.progress;
      console.log('📊 Deep Scan Progress:', request.progress);
    }
    sendResponse({ status: 'updated' });
  } else if (request.action === 'deepScanCompleted') {
    // Deep scan complete
    deepScanState.isRunning = false;
    deepScanState.results = request.data;
    console.log('✅ Deep Scan complete and saved in background');

    // Save to history
    if (sender.tab) {
      handleManualScan(request.data, sender.tab);
    }
    sendResponse({ status: 'completed' });
  } else if (request.action === 'getDeepScanState') {
    // Return current deep scan state
    sendResponse({
      status: 'success',
      state: deepScanState
    });
  } else if (request.action === 'markTokenViewed') {
// Mark token as viewed
    markTokenAsViewed(request.tokenId, request.tokenValue).then(result => {
      sendResponse(result);
    });
    return true;
  }
  // Export and statistics actions
  else if (request.action === 'exportHistory') {
    exportHistory().then(sendResponse);
    return true;
  } else if (request.action === 'clearHistory') {
    clearHistory().then(sendResponse);
    return true;
  } else if (request.action === 'getStats') {
    getStats().then(sendResponse);
    return true;
  } else if (request.action === 'exportForPentest') {
    exportForPentest().then(sendResponse);
    return true;
  } else if (request.action === 'exportNucleiTemplate') {
    exportNucleiTemplate().then(sendResponse);
    return true;
  }
  return true;
});

// Process found tokens
async function handleTokensFound(foundTokens, tab) {
  if (!tab) {
    console.error('❌ handleTokensFound: tab is undefined');
    return;
  }

  const { settings } = await chrome.storage.local.get('settings');
  if (!settings) {
    console.error('❌ handleTokensFound: settings not found');
    return;
  }

  // Validate foundTokens structure
  if (!foundTokens || !foundTokens.tokens || !Array.isArray(foundTokens.tokens)) {
    console.error('❌ Invalid foundTokens structure:', foundTokens);
  }

  if (foundTokens.tokens.length === 0) {
    console.log('✅ No tokens found in:', tab.url);
    return;
  }

    console.log(`🔍 ${foundTokens.tokens.length} tokens found in:`, tab.url);

  // Check if there are valid tokens
  const validTokens = foundTokens.tokens.filter(t => t.validation?.valid === true);
  const hasValidTokens = validTokens.length > 0;

  if (hasValidTokens) {
    console.log(`⚠️ CRITICAL ALERT: ${validTokens.length} valid token(s) found!`);

    // Alert badge for valid tokens
    chrome.action.setBadgeText({ text: '⚠️' });
    chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });

    // Critical notification
    if (settings.notificationsEnabled) {
      await sendCriticalNotification(validTokens.length, foundTokens.tokens.length, tab);
    }
  } else {
    // Send normal notification
    if (settings.notificationsEnabled) {
      await sendNotification(foundTokens.tokens.length, tab);
    }
  }

  // Save to history
  if (settings.saveHistory) {
    await saveToHistory(foundTokens, tab);
  }

  // Send to Discord
  if (settings.discordWebhookEnabled && settings.discordWebhookUrl) {
    await sendToDiscord(foundTokens, tab, settings.discordWebhookUrl);
  }
}

// Process manual scan
async function handleManualScan(foundTokens, tab) {
  if (!tab) {
    console.error('❌ handleManualScan: tab is undefined');
    return;
  }

  const { settings } = await chrome.storage.local.get('settings');
  if (!settings) {
    console.error('❌ handleManualScan: settings not found');
    return;
  }

  // Validate foundTokens structure
  if (!foundTokens || !foundTokens.tokens || !Array.isArray(foundTokens.tokens)) {
    console.error('❌ Invalid foundTokens structure:', foundTokens);
  }

    console.log(`📋 Manual scan: ${foundTokens.tokens.length} tokens in:`, tab.url);

  // Save to history
  if (settings.saveHistory) {
    await saveToHistory(foundTokens, tab);
  }

  // Send to Discord if configured
  if (settings.discordWebhookEnabled && settings.discordWebhookUrl) {
    await sendToDiscord(foundTokens, tab, settings.discordWebhookUrl);
  }
}

// Save tokens to history
async function saveToHistory(foundTokens, tab) {
  if (!tab) {
    console.error('❌ saveToHistory: tab is undefined');
    return;
  }

  try {
    const { history = [] } = await chrome.storage.local.get('history');

    const entry = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      url: tab.url || 'Unknown URL',
      title: tab.title || 'Unknown title',
      favicon: tab.favIconUrl || '',
      tokensCount: foundTokens.tokens?.length || 0,
      tokens: foundTokens.tokens || [],
      scriptsAnalyzed: foundTokens.scriptsAnalyzed || 0
    };

    // Add at the beginning of the array (most recent first)
    history.unshift(entry);

    // Limit history to 500 entries
    const limitedHistory = history.slice(0, 500);

    await chrome.storage.local.set({ history: limitedHistory });
    console.log('💾 Tokens saved to history');
  } catch (error) {
    console.error('❌ Error saving history:', error);
  }
}

// Send notification
async function sendNotification(tokenCount, tab) {
  if (!tab) {
    console.error('❌ sendNotification: tab is undefined');
    return;
  }

  try {
    const notificationId = `tokens-${Date.now()}`;
    const tabInfo = tab.title || tab.url || 'Unknown site';

    await chrome.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🔍 Hardcoded Tokens Detected!',
      message: `Found ${tokenCount} token(s) in:\n${truncateText(tabInfo, 60)}`,
      priority: 2,
      requireInteraction: true,
      buttons: [
        { title: '👁️ View Details' },
        { title: '📋 View History' }
      ]
    });

    console.log('🔔 Notification sent');
  } catch (error) {
    console.error('❌ Error sending notification:', error);
  }
}

// Send critical notification for valid tokens
async function sendCriticalNotification(validCount, totalCount, tab) {
  if (!tab) {
    console.error('❌ sendCriticalNotification: tab is undefined');
    return;
  }

  try {
    const notificationId = `critical-${Date.now()}`;
    const tabInfo = tab.title || tab.url || 'Unknown site';

    await chrome.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🚨 CRITICAL ALERT: Valid Tokens Detected!',
      message: `⚠️ ${validCount} VALID token(s) out of ${totalCount} found in:\n${truncateText(tabInfo, 50)}\n\nIMMEDIATE ACTION REQUIRED!`,
      priority: 2,
      requireInteraction: true,
      buttons: [
        { title: '🚨 View Now' },
        { title: '📋 View History' }
      ]
    });

    console.log('🚨 Critical notification sent');
  } catch (error) {
    console.error('❌ Error sending critical notification:', error);
  }
}

// Listener for notification clicks
chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
  if (buttonIndex === 0) {
    // View Details - open popup
    const windows = await chrome.windows.getAll();
    if (windows.length > 0) {
      chrome.action.openPopup();
    }
  } else if (buttonIndex === 1) {
    // View History - open history page
    chrome.tabs.create({ url: 'history.html' });
  }
  chrome.notifications.clear(notificationId);
});

// Send to Discord Webhook
async function sendToDiscord(foundTokens, tab, webhookUrl) {
  if (!tab) {
    console.error('❌ sendToDiscord: tab is undefined');
    return;
  }

  try {
    // Validate foundTokens structure
    if (!foundTokens || !foundTokens.tokens || !Array.isArray(foundTokens.tokens)) {
      console.error('❌ sendToDiscord: Invalid foundTokens structure:', foundTokens);
      return;
    }

    const tabUrl = tab.url || 'Unknown URL';
    const tabTitle = tab.title || 'No title';

    // Count validated tokens
    const validTokens = foundTokens.tokens.filter(t => t.validation?.valid === true);
    const invalidTokens = foundTokens.tokens.filter(t => t.validation?.valid === false);
    const unvalidatedTokens = foundTokens.tokens.filter(t => t.validation?.valid === null || t.validation?.valid === undefined);

    // Define embed color based on severity
    let embedColor = 0xF5576C; // Default pink
    if (validTokens.length > 0) {
      embedColor = 0xFF0000; // Red for valid tokens
    }

    const embed = {
      title: validTokens.length > 0 ? '🚨 CRITICAL ALERT: Valid Tokens Detected!' : '🔍 Hardcoded Tokens Detected by manojxshrestha',
      description: `**${foundTokens.tokens.length}** token(s) found${validTokens.length > 0 ? `\n\n⚠️ **${validTokens.length} VALID AND ACTIVE TOKEN(S)!**` : ''}`,
      color: embedColor,
      url: tabUrl,
      fields: [
        {
          name: '🌐 Site',
          value: truncateText(tabTitle, 256),
          inline: false
        },
        {
          name: '🔗 URL',
          value: truncateText(tabUrl, 256),
          inline: false
        },
        {
          name: '📄 Scripts Analyzed',
          value: (foundTokens.scriptsAnalyzed || 0).toString(),
          inline: true
        },
        {
          name: '🔑 Tokens Found',
          value: foundTokens.tokens.length.toString(),
          inline: true
        }
      ],
      timestamp: new Date().toISOString(),
      footer: {
        text: 'manojxshrestha CredStalker'
      }
    };

    // Add validation summary if there are validated tokens
    if (validTokens.length > 0 || invalidTokens.length > 0 || unvalidatedTokens.length > 0) {
      embed.fields.push({
        name: '🔐 Validation Status',
        value: `✅ Valid: **${validTokens.length}**\n❌ Invalid: **${invalidTokens.length}**\n⚠️ Not validated: **${unvalidatedTokens.length}**`,
        inline: false
      });
    }

    // Add tokens to embed (maximum 10 to not exceed limit)
    const tokensToShow = foundTokens.tokens.slice(0, 10);
    tokensToShow.forEach((token, index) => {
      const tokenValue = truncateText(token.value, 100);
      const scriptUrl = truncateText(token.scriptUrl, 200);

      // Determine validation status
      let validationIcon = '⚠️';
      let validationStatus = 'Not validated';

      if (token.validation) {
        if (token.validation.valid === true) {
          validationIcon = '✅';
          validationStatus = `**VALID**: ${token.validation.status}`;
          if (token.validation.severity) {
            validationStatus += ` (${token.validation.severity})`;
          }
        } else if (token.validation.valid === false) {
          validationIcon = '❌';
          validationStatus = `Invalid: ${token.validation.status}`;
        } else {
          validationIcon = '⚠️';
          validationStatus = token.validation.status || 'Could not validate';
        }
      }

      embed.fields.push({
        name: `${getTypeEmoji(token.type)} ${validationIcon} Token ${index + 1}: ${token.type}`,
        value: `\`\`\`\n${tokenValue}\n\`\`\`\n📄 Script: ${scriptUrl}\n🔐 **Status:** ${validationStatus}`,
        inline: false
      });
    });

    // If there are more tokens, add note
    if (foundTokens.tokens.length > 10) {
      embed.fields.push({
        name: '⚠️ Warning',
        value: `Plus ${foundTokens.tokens.length - 10} more token(s) found. See the full history in the extension.`,
        inline: false
      });
    }

    const payload = {
      username: 'manojxshrestha Token Detector',
      avatar_url: 'https://cdn.discordapp.com/embed/avatars/0.png',
      embeds: [embed]
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      console.log('✅ Tokens sent to Discord');
    } else {
      console.error('❌ Error sending to Discord:', response.status, response.statusText);
    }
    } catch (error) {
      console.error('❌ Error sending to Discord:', error);
    }
}

// Helper functions
function truncateText(text, maxLength) {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
}

function getTypeEmoji(type) {
  const emojis = {
    'API_KEY': '🔑',
    'JWT': '🎫',
    'AWS': '☁️',
    'GITHUB': '🐙',
    'GITLAB': '🦊',
    'VERCEL': '▲',
    'SUPABASE': '⚡',
    'SLACK': '💬',
    'STRIPE': '💳',
    'FIREBASE': '🔥',
    'GOOGLE': '🔍',
    'FACEBOOK': '👤',
    'TWITTER': '🐦',
    'PASSWORD': '🔐',
    'SECRET': '🤫',
    'TOKEN': '🎟️',
    'PRIVATE_KEY': '🔒'
  };
  return emojis[type] || '⚠️';
}

// Initialize extension state (Badge and Proxy) after settings are ready
async function initializeExtensionState() {
  try {
    const { settings } = await chrome.storage.local.get('settings');

    if (!settings) {
      console.log('⚠️ Settings not yet initialized, waiting...');
      return;
    }

    // Configure badge based on autoScan
    if (settings.autoScanEnabled) {
      chrome.action.setBadgeText({ text: 'AUTO' });
      chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
    }

    // Configure proxy if enabled
    if (settings.proxyEnabled) {
      await configureProxy(settings);
    }

    console.log('✅ Extension state initialized');
  } catch (error) {
    console.error('❌ Error initializing extension state:', error);
  }
}

// Call initialization with delay to ensure onInstalled finishes
setTimeout(initializeExtensionState, 100);

// Listener for settings changes
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local' && changes.settings && changes.settings.newValue) {
    const newSettings = changes.settings.newValue;
    if (newSettings.autoScanEnabled) {
      chrome.action.setBadgeText({ text: 'AUTO' });
      chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
    } else {
      chrome.action.setBadgeText({ text: '' });
    }

    // Update proxy configuration
    const oldSettings = changes.settings.oldValue || {};
    if (newSettings.proxyEnabled !== oldSettings.proxyEnabled ||
        newSettings.proxyHost !== oldSettings.proxyHost ||
        newSettings.proxyPort !== oldSettings.proxyPort) {
      configureProxy(newSettings);
    }
  }
});

// Configure proxy
async function configureProxy(settings) {
  try {
    if (!settings) {
      console.error('❌ configureProxy: settings is undefined');
      return;
    }

    if (settings.proxyEnabled && settings.proxyHost && settings.proxyPort) {
      const proxyConfig = {
        mode: "fixed_servers",
        rules: {
          singleProxy: {
            scheme: "http",
            host: settings.proxyHost,
            port: parseInt(settings.proxyPort, 10)
          },
          bypassList: []
        }
      };

      await chrome.proxy.settings.set({
        value: proxyConfig,
        scope: 'regular'
      });

      console.log(`✅ Proxy configured: ${settings.proxyHost}:${settings.proxyPort}`);

      // Update badge to indicate active proxy
      chrome.action.setBadgeText({ text: 'PROXY' });
      chrome.action.setBadgeBackgroundColor({ color: '#FF6B35' });
    } else {
      // Disable proxy
      await chrome.proxy.settings.clear({
        scope: 'regular'
      });

      console.log('✅ Proxy disabled');

      // Restore previous badge
      if (settings && settings.autoScanEnabled) {
        chrome.action.setBadgeText({ text: 'AUTO' });
        chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
      } else {
        chrome.action.setBadgeText({ text: '' });
      }
    }
  } catch (error) {
    console.error('❌ Error configuring proxy:', error);
  }
}

// Removed: initialization moved to initializeExtensionState()
// Removed: duplicate listener merged with the main one

// Export history
async function exportHistory() {
  try {
    const { history = [] } = await chrome.storage.local.get('history');
    return {
      success: true,
      data: history,
      count: history.length
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Clear history
async function clearHistory() {
  try {
    await chrome.storage.local.set({ history: [] });
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Get statistics
async function getStats() {
  try {
    const { history = [] } = await chrome.storage.local.get('history');

    // Filter valid URLs for uniqueSites
    const validUrls = history
      .map(e => {
        try {
          return new URL(e.url).hostname;
        } catch {
          return null;
        }
      })
      .filter(hostname => hostname !== null);

    const stats = {
      totalScans: history.length,
      totalTokens: history.reduce((sum, entry) => sum + entry.tokensCount, 0),
      uniqueSites: [...new Set(validUrls)].length,
      lastScan: history[0] ? history[0].timestamp : null
    };

    return { success: true, stats };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Mark token as viewed in history
async function markTokenAsViewed(tokenId, tokenValue) {
  try {
    const { history = [] } = await chrome.storage.local.get('history');
    let found = false;

    // Search and update the token in all history entries
    for (const entry of history) {
      for (const token of entry.tokens) {
        if ((token.id && token.id === tokenId) || token.value === tokenValue) {
          token.viewed = true;
          token.viewedAt = new Date().toISOString();
          found = true;
        }
      }
    }

    if (found) {
      await chrome.storage.local.set({ history });
      console.log('💾 Token marked as viewed in history');
      return { success: true, message: 'Token marked as viewed' };
    } else {
      console.warn('⚠️ Token not found in history');
      return { success: false, message: 'Token not found' };
    }
  } catch (error) {
    console.error('❌ Error marking token as viewed:', error);
    return { success: false, error: error.message };
  }
}

// ========================================
// EXPORT FOR PENTEST TOOLS
// ========================================

// Export in optimized format for pentest (structured JSON)
async function exportForPentest() {
  try {
    const { history = [] } = await chrome.storage.local.get('history');

    // Group tokens by type and severity
    const tokensBySeverity = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: []
    };

    const endpoints = [];
    const domains = new Set();

    for (const entry of history) {
      domains.add(new URL(entry.url).hostname);

      for (const token of entry.tokens) {
        const severity = token.severity || 'MEDIUM';

        tokensBySeverity[severity].push({
          type: token.type,
          value: token.value,
          url: entry.url,
          scriptUrl: token.scriptUrl,
          timestamp: token.timestamp,
          validation: token.validation
        });
      }

      // Collect endpoints
      if (entry.endpoints) {
        endpoints.push(...entry.endpoints);
      }
    }

    const pentestData = {
      generated: new Date().toISOString(),
      tool: 'manojxshrestha CredStalker',
      summary: {
        total_tokens: history.reduce((sum, e) => sum + e.tokensCount, 0),
        critical: tokensBySeverity.CRITICAL.length,
        high: tokensBySeverity.HIGH.length,
        medium: tokensBySeverity.MEDIUM.length,
        low: tokensBySeverity.LOW.length,
        domains_scanned: domains.size,
        endpoints_found: endpoints.length
      },
      tokens_by_severity: tokensBySeverity,
      endpoints,
      domains: Array.from(domains)
    };

    return {
      success: true,
      data: pentestData,
      filename: `pentest-tokens-${Date.now()}.json`
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Export Nuclei template for found endpoints
async function exportNucleiTemplate() {
  try {
    const { history = [] } = await chrome.storage.local.get('history');

    const endpoints = [];
    for (const entry of history) {
      if (entry.endpoints) {
        endpoints.push(...entry.endpoints.map(e => e.url));
      }
    }

    const uniqueEndpoints = [...new Set(endpoints)];

    const nucleiTemplate = {
      id: 'hardcoded-tokens-scan',
      info: {
        name: 'CredStalker: Tokens and Endpoints Scanner',
        author: 'manojxshrestha',
        severity: 'high',
        description: 'Scans for hardcoded tokens and sensitive endpoints discovered by manojxshrestha Token Detector',
        tags: ['tokens', 'secrets', 'hardcoded']
      },
      requests: [
        {
          method: 'GET',
          path: uniqueEndpoints.slice(0, 50), // Limit to 50 endpoints
          matchers: [
            {
              type: 'status',
              status: [200]
            }
          ]
        }
      ]
    };

    return {
      success: true,
      data: nucleiTemplate,
      filename: `nuclei-template-${Date.now()}.yaml`
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}
