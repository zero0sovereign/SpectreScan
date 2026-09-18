const https = require('https');

// Unified Set for fast O(1) in-memory checks
let openphishUrls = new Set();
let urlhausUrls = new Set();
let lastUpdated = null;

const OPENPHISH_FEED = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
const URLHAUS_FEED = 'https://urlhaus.abuse.ch/downloads/text/';

// Generic fetcher for text-based feeds
function fetchFeed(feedUrl) {
    return new Promise((resolve) => {
        https.get(feedUrl, (res) => {
            // URLhaus might redirect (301/302)
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                return resolve(fetchFeed(res.headers.location));
            }

            if (res.statusCode !== 200) {
                console.error(`[Feed Error] Status ${res.statusCode} for ${feedUrl}`);
                return resolve(new Set());
            }

            let rawData = '';
            res.on('data', (chunk) => { rawData += chunk; });
            res.on('end', () => {
                const lines = rawData
                    .split(/\r?\n/)
                    // Remove blank lines and URLhaus comment lines starting with '#'
                    .filter(line => line.trim().length > 0 && !line.trim().startsWith('#'))
                    .map(url => url.trim().toLowerCase());

                resolve(new Set(lines));
            });
        }).on('error', (err) => {
            console.error(`[Network Error] Failed fetching ${feedUrl}:`, err.message);
            resolve(new Set());
        });
    });
}

// Downloads both feeds and saves them in memory
async function syncAllDatabases() {
    console.log('[Threat Intel] Syncing threat databases...');
    const [phishSet, hausSet] = await Promise.all([
        fetchFeed(OPENPHISH_FEED),
        fetchFeed(URLHAUS_FEED)
    ]);

    if (phishSet.size > 0) openphishUrls = phishSet;
    if (hausSet.size > 0) urlhausUrls = hausSet;
    lastUpdated = new Date();

    console.log(`[Database Ready] OpenPhish: ${openphishUrls.size} URLs | URLhaus: ${urlhausUrls.size} URLs.`);
}

// Initial pull on server boot
syncAllDatabases();

// Re-sync feeds every 1 hour
setInterval(syncAllDatabases, 60 * 60 * 1000);

// Detection helper for matching either exact URL or hostname
function checkMatch(targetUrl, databaseSet) {
    const isExact = databaseSet.has(targetUrl);
    if (isExact) return { matched: true, matchType: 'Exact URL' };

    try {
        const targetHost = new URL(targetUrl).hostname;
        for (const badUrl of databaseSet) {
            try {
                if (new URL(badUrl).hostname === targetHost) {
                    return { matched: true, matchType: 'Domain / Hostname Match' };
                }
            } catch {
                // Ignore malformed entries
            }
        }
    } catch {
        // Bad target URL format
    }

    return { matched: false, matchType: 'None' };
}

// Main checking function used by server.js
module.exports = async function checkBlacklist(targetUrl) {
    const cleanTarget = targetUrl.trim().toLowerCase();

    const phishCheck = checkMatch(cleanTarget, openphishUrls);
    const hausCheck = checkMatch(cleanTarget, urlhausUrls);

    const isFlagged = phishCheck.matched || hausCheck.matched;

    // Detect which feeds identified the threat
    const sourcesFound = [];
    if (phishCheck.matched) sourcesFound.push('OpenPhish (Phishing)');
    if (hausCheck.matched) sourcesFound.push('URLhaus (Malware)');

    return {
        safe: !isFlagged,
        isMalicious: isFlagged,
        matchedFeeds: sourcesFound.length > 0 ? sourcesFound : ['None'],
        matchType: phishCheck.matchType !== 'None' ? phishCheck.matchType : hausCheck.matchType,
        totalThreatUrls: openphishUrls.size + urlhausUrls.size,
        lastSynced: lastUpdated
    };
};
