const https = require('https');

// In-memory set for instantaneous O(1) lookups
let blacklistedUrls = new Set();
let lastUpdated = null;

const FEED_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';

// Downloads the raw OpenPhish feed and loads it into memory
function syncDatabase() {
    https.get(FEED_URL, (res) => {
        if (res.statusCode !== 200) {
            console.error(`Failed to pull feed. Status: ${res.statusCode}`);
            return;
        }

        let rawData = '';
        res.on('data', (chunk) => { rawData += chunk; });
        res.on('end', () => {
            const lines = rawData.split(/\r?\n/).filter(line => line.trim().length > 0);
            blacklistedUrls = new Set(lines.map(url => url.trim().toLowerCase()));
            lastUpdated = new Date();
            console.log(`[Database Ready] Loaded ${blacklistedUrls.size} phishing URLs from OpenPhish.`);
        });
    }).on('error', (err) => {
        console.error('Error fetching database feed:', err.message);
    });
}

// Download the feed immediately on server launch
syncDatabase();

// Re-sync the database automatically every 1 hour
setInterval(syncDatabase, 60 * 60 * 1000);

// Function that server.js runs on every scan
module.exports = async function checkBlacklist(targetUrl) {
    const cleanTarget = targetUrl.trim().toLowerCase();

    // 1. Direct match check
    const isExactMatch = blacklistedUrls.has(cleanTarget);

    // 2. Domain / Hostname match check
    let isDomainMatch = false;
    try {
        const targetHost = new URL(cleanTarget).hostname;
        for (const badUrl of blacklistedUrls) {
            try {
                if (new URL(badUrl).hostname === targetHost) {
                    isDomainMatch = true;
                    break;
                }
            } catch {
                // Ignore malformed lines in the public feed
            }
        }
    } catch {
        // Handled if target URL lacks protocol
    }

    const flagged = isExactMatch || isDomainMatch;

    return {
        safe: !flagged,
        isPhishing: flagged,
        database: 'OpenPhish Public Feed',
        matchType: isExactMatch ? 'Exact URL' : (isDomainMatch ? 'Domain Match' : 'None'),
        totalUrlsLoaded: blacklistedUrls.size,
        lastSynced: lastUpdated
    };
};
