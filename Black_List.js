const FEED_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';

let urlSet = new Set();
let hostSet = new Set();
let lastUpdated = null;

async function syncDatabase() 
{
    try 
    {
        const res = await fetch(FEED_URL, { signal: AbortSignal.timeout(30_000) });
        if (!res.ok) throw new Error(`status ${res.status}`);

        const text = await res.text();
        const urls = new Set();
        const hosts = new Set();

        for (const line of text.split(/\r?\n/)) 
        {
            const u = line.trim().toLowerCase();
            if (!u) continue;
            urls.add(u);
            try { hosts.add(new URL(u).hostname); } catch { /* skip malformed line */ }
        }

        // swap atomically; on failure we keep serving the old data
        urlSet = urls;
        hostSet = hosts;
        lastUpdated = new Date();
        console.log(`[Blacklist] Loaded ${urls.size} URLs / ${hosts.size} hosts`);
    } 
    
    catch (err) 
    {
        console.error('[Blacklist] Feed sync failed:', err.message);
    }
}

syncDatabase();
setInterval(syncDatabase, 60 * 60 * 1000).unref();

// Synchronous on purpose: it's just Set lookups.
function blacklistCheck(targetUrl) {
    const target = targetUrl.trim().toLowerCase();

    const exact = urlSet.has(target);

    let domain = false;
    if (!exact) {
        try { domain = hostSet.has(new URL(target).hostname); } catch { /* ignore */ }
    }

    return {
        safe: !(exact || domain),
        isPhishing: exact || domain,
        // A hostname-only hit can be a false positive on shared hosts
        // (sites.google.com, github.io, ...), so server.js treats it as
        // "suspicious", not "malicious".
        matchType: exact ? 'Exact URL' : (domain ? 'Domain Match' : 'None'),
        database: 'OpenPhish Public Feed',
        totalUrlsLoaded: urlSet.size,
        lastSynced: lastUpdated
    };
}

module.exports = blacklistCheck;
