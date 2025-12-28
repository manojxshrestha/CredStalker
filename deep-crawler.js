// Deep Crawler - manojxshrestha CredStalker
// Deep crawler for JavaScript analysis with depth 10

class DeepCrawler {
  constructor(maxDepth = 10) {
    this.maxDepth = maxDepth;
    this.visitedUrls = new Set();
    this.foundScripts = new Set();
    this.queue = [];
    this.depth = 0;
  }

  // Start deep crawler
  async crawl(startUrl = window.location.href) {
    console.log(`🕷️ Starting Deep Crawler (depth: ${this.maxDepth})`);

    this.queue.push({ url: startUrl, depth: 0 });
    const allScripts = [];

    while (this.queue.length > 0) {
      const { url, depth } = this.queue.shift();

      if (depth > this.maxDepth || this.visitedUrls.has(url)) {
        continue;
      }

      console.log(`🔍 Crawling [depth ${depth}]: ${url}`);
      this.visitedUrls.add(url);

      try {
        const scripts = await this.extractScriptsFromPage(url, depth);
        allScripts.push(...scripts);

        // If maximum depth not reached, search for more links
        if (depth < this.maxDepth) {
          const links = await this.extractLinks(url);
          for (const link of links) {
            if (!this.visitedUrls.has(link) && this.isSameDomain(link, startUrl)) {
              this.queue.push({ url: link, depth: depth + 1 });
            }
          }
        }
      } catch (error) {
        console.warn(`⚠️ Error processing ${url}:`, error.message);
        // Detailed error log for debugging
        if (error.stack) {
          console.debug('Stack trace:', error.stack);
        }
      }

      // Delay to avoid overloading
      await this.sleep(100);
    }

    console.log(`✅ Crawler complete: ${allScripts.length} scripts found in ${this.visitedUrls.size} pages`);
    return allScripts;
  }

  // Extract scripts from a page
  async extractScriptsFromPage(url, depth) {
    const scripts = [];

    try {
      let htmlContent;

      // If it's the current page, use DOM
      if (url === window.location.href) {
        htmlContent = document.documentElement.outerHTML;
      } else {
        // Fetch external page
        const response = await fetch(url);
        htmlContent = await response.text();
      }

       // Parse HTML
       let doc;
       try {
         const parser = new DOMParser();
         doc = parser.parseFromString(htmlContent, 'text/html');
       } catch (parseError) {
         console.warn(`⚠️ Error parsing HTML for ${url}:`, parseError.message);
         return scripts; // Return empty scripts if parsing fails
       }

      // Find all scripts
      const scriptElements = doc.querySelectorAll('script');

      for (const script of scriptElements) {
        // Inline script
        if (script.textContent && script.textContent.trim()) {
          const scriptData = {
            type: 'inline',
            url: url,
            content: script.textContent,
            depth: depth,
            size: script.textContent.length,
            foundAt: new Date().toISOString()
          };

          scripts.push(scriptData);
          this.foundScripts.add(JSON.stringify({ url, type: 'inline' }));
        }

        // External script
        if (script.src) {
          const scriptUrl = this.resolveUrl(script.src, url);
          const scriptKey = JSON.stringify({ url: scriptUrl, type: 'external' });

          // Ignore known third-party scripts and source maps
          if (scriptUrl.includes('.map') ||
              scriptUrl.includes('google-analytics') ||
              scriptUrl.includes('googletagmanager') ||
              scriptUrl.includes('facebook.net') ||
              scriptUrl.includes('twitter.com') ||
              scriptUrl.includes('linkedin.com') ||
              scriptUrl.includes('hotjar.com') ||
              scriptUrl.includes('clarity.ms') ||
              scriptUrl.includes('redditstatic.com') ||
              scriptUrl.includes('quora.com') ||
              scriptUrl.includes('marketo.net') ||
              scriptUrl.includes('ads-twitter.com')) {
            continue;
          }

          if (!this.foundScripts.has(scriptKey)) {
            try {
              const response = await fetch(scriptUrl);
              const content = await response.text();

              const scriptData = {
                type: 'external',
                url: scriptUrl,
                content: content,
                depth: depth,
                size: content.length,
                foundAt: new Date().toISOString()
              };

              scripts.push(scriptData);
              this.foundScripts.add(scriptKey);

              // Analyze sourceMappingURL and fetch source maps
              const sourceMapMatch = content.match(/\/\/# sourceMappingURL=(.+)/);
              if (sourceMapMatch) {
                await this.fetchSourceMap(scriptUrl, sourceMapMatch[1], scripts, depth);
              }

            } catch (error) {
              // Silently ignore CORS and network errors
              // Only log unexpected errors
              if (!error.message.includes('CORS') &&
                  !error.message.includes('Failed to fetch') &&
                  !error.message.includes('NetworkError')) {
                console.warn(`⚠️ Error fetching script: ${scriptUrl}`, error.message);
              }
            }
          }
        }
      }

      // Search for scripts in onclick, onerror, etc attributes
      const elementsWithEvents = doc.querySelectorAll('[onclick], [onerror], [onload], [onmouseover]');
      for (const elem of elementsWithEvents) {
        for (const attr of ['onclick', 'onerror', 'onload', 'onmouseover']) {
          const code = elem.getAttribute(attr);
          if (code) {
            scripts.push({
              type: 'event-handler',
              url: url,
              content: code,
              depth: depth,
              size: code.length,
              attribute: attr,
              foundAt: new Date().toISOString()
            });
          }
        }
      }

       // Search for JavaScript in URLs (javascript:)
       const jsLinks = doc.querySelectorAll('a[href^="javascript:"]');
       for (const link of jsLinks) {
         const code = link.getAttribute('href').substring(11); // Remove 'javascript:'
         try {
           const decodedCode = decodeURIComponent(code);
           scripts.push({
             type: 'javascript-url',
             url: url,
             content: decodedCode,
             depth: depth,
             size: decodedCode.length,
             foundAt: new Date().toISOString()
           });
         } catch (decodeError) {
           console.warn(`⚠️ Error decoding JavaScript URL: ${code}`, decodeError.message);
         }
       }

    } catch (error) {
      console.error(`❌ Error extracting scripts from ${url}:`, error.message);
      if (error.stack) {
        console.debug('Stack trace:', error.stack);
      }
    }

    return scripts;
  }

  // Fetch and analyze source maps
  async fetchSourceMap(scriptUrl, sourceMapPath, scripts, depth) {
    try {
      const sourceMapUrl = this.resolveUrl(sourceMapPath, scriptUrl);
      const response = await fetch(sourceMapUrl);
      const sourceMap = await response.json();

      // Source maps contain original code
      if (sourceMap.sourcesContent) {
        for (let i = 0; i < sourceMap.sourcesContent.length; i++) {
          const content = sourceMap.sourcesContent[i];
          if (content) {
            scripts.push({
              type: 'sourcemap',
              url: sourceMapUrl,
              originalFile: sourceMap.sources[i],
              content: content,
              depth: depth,
              size: content.length,
              foundAt: new Date().toISOString()
            });
          }
        }
      }
    } catch (error) {
      // Silently ignore errors when fetching source maps
      // Source maps usually cause CORS errors and are not critical
      if (!error.message.includes('CORS') &&
          !error.message.includes('Failed to fetch') &&
          !error.message.includes('NetworkError') &&
          !error.message.includes('JSON')) {
        console.warn(`⚠️ Error fetching source map: ${sourceMapPath}`, error.message);
      }
    }
  }

  // Extract links from a page
  async extractLinks(url) {
    const links = [];

    try {
      const response = await fetch(url);
      const html = await response.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');

      const anchors = doc.querySelectorAll('a[href]');
      for (const anchor of anchors) {
        const href = anchor.getAttribute('href');
        if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
          const absoluteUrl = this.resolveUrl(href, url);
          links.push(absoluteUrl);
        }
      }
    } catch (error) {
      console.warn(`⚠️ Error extracting links from ${url}`, error.message);
    }

    return links;
  }

  // Resolve relative URL to absolute
  resolveUrl(relativeUrl, baseUrl) {
    try {
      return new URL(relativeUrl, baseUrl).href;
    } catch {
      return relativeUrl;
    }
  }

  // Check if it's the same domain
  isSameDomain(url1, url2) {
    try {
      const domain1 = new URL(url1).hostname;
      const domain2 = new URL(url2).hostname;
      return domain1 === domain2;
    } catch {
      return false;
    }
  }

  // Sleep helper
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Get crawler statistics
  getStats() {
    return {
      pagesVisited: this.visitedUrls.size,
      scriptsFound: this.foundScripts.size,
      queueSize: this.queue.length
    };
  }
}

// Export for global use (compatible with Chrome extensions)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DeepCrawler;
}

// Make globally available as well
if (typeof window !== 'undefined') {
  window.DeepCrawler = DeepCrawler;
}

// Export as ES6 module
export default DeepCrawler;
export { DeepCrawler };
