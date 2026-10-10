const express = require('express');
const cors = require('cors');
const path = require('path');

const blacklistCheck = require('./Black_List');
const heuristicsCheck = require('./Heuristics');
const vmSandboxCheck = require('./VM_Check');
const ScanQueue = require('./queue');

const PORT = Number(process.env.PORT || 3000);

// Keep this EQUAL to the VM's WORKERS setting (default 3).
const SCAN_CONCURRENCY = Number(process.env.SCAN_CONCURRENCY || 3);

const MAX_QUEUE = Number(process.env.MAX_QUEUE || 300);
const MAX_URL_LENGTH = 2048;
const MAX_SSE_CLIENTS = Number(process.env.MAX_SSE_CLIENTS || 1000);

// forgets old results faster. Well below the 3-4 GB budget.
const MEM_SOFT_LIMIT_MB = Number(process.env.MEM_SOFT_LIMIT_MB || 2000);

const app = express();
app.use(cors());
app.use(express.json({ limit: '8kb' }));


app.use(express.static(path.join(__dirname, 'frontend'), { index: 'FRONT_PAGE.HTML' }));

function buildVerdict({ blacklist, heuristics, vmSandbox }) 
{
    const reasons = [];
    let level = 0; // 0 clean, 1 suspicious, 2 malicious

    const bump = (l, reason) => {
        if (l > level) level = l;
        reasons.push(reason);
    };

    if (blacklist.matchType === 'Exact URL') bump(2, 'URL is listed in the OpenPhish feed');
    
    else if (blacklist.matchType === 'Domain Match') bump(1, 'Hostname appears in the OpenPhish feed');

    if (heuristics.suspicious) bump(1, `URL heuristics risk score is ${heuristics.riskScore}`);

    const skipped = Boolean(vmSandbox && vmSandbox.skipped);
    const vmRan = Boolean(vmSandbox && vmSandbox.working && !skipped);

    if (vmRan) 
    {
        const s = vmSandbox.suspicionScore || 0;
        
        if (s >= 70) bump(2, `Sandbox behavior score is ${s}/100`);
        
        else if (s >= 40) bump(1, `Sandbox behavior score is ${s}/100`);
    }

    let verdict = ['clean', 'suspicious', 'malicious'][level];

    // "Looks clean" is only trustworthy if the sandbox really saw the page.
    if (level === 0 && !skipped) 
    {
        if (!vmRan) 
        {
            verdict = 'unverified';
            reasons.push(`Sandbox unavailable (${(vmSandbox && vmSandbox.error) || 'unknown error'})`);
        } 
        
        else if (vmSandbox.navigationError || vmSandbox.timedOut) 
        {
            verdict = 'unverified';
            reasons.push('The page did not finish loading within the sandbox time limit, so it could not be fully analyzed');
        }
    }

    if (reasons.length === 0) reasons.push('No indicators found');
    
    return { verdict, reasons };
}

function finalize(job, vmSandbox, emit) 
{
    const { blacklist, heuristics } = job.partial;
    const { verdict, reasons } = buildVerdict({ blacklist, heuristics, vmSandbox });

    emit('verdict', { verdict, reasons });

    return{
        verdict,
        reasons,
        durationMs: Date.now() - job.createdAt,
        results: { blacklist, heuristics, vmSandbox }
    };
}

async function quickStage(job, emit) 
{
    const blacklist = blacklistCheck(job.url);          // O(1), in memory
    job.partial.blacklist = blacklist;
    emit('blacklist', blacklist);

    const heuristics = await heuristicsCheck(job.url);  // pure CPU, microseconds
    job.partial.heuristics = heuristics;
    emit('heuristics', heuristics);

    // An exact phishing-feed hit is already conclusive -> skip the sandbox.
    if (blacklist.matchType === 'Exact URL') 
    {
        const vmSandbox = { skipped: true, reason: 'exact blacklist match, sandbox not needed' };
        emit('sandbox', vmSandbox);
        return finalize(job, vmSandbox, emit);
    }

    return null; // continue to the sandbox queue
}

async function sandboxStage(job, emit) 
{
    emit('sandbox_start', {});

    const vmSandbox = await vmSandboxCheck(job.url);
    emit('sandbox', vmSandbox);

    return finalize(job, vmSandbox, emit);
}

const queue = new ScanQueue({
    quick: quickStage,
    handler: sandboxStage,
    concurrency: SCAN_CONCURRENCY,
    maxQueue: MAX_QUEUE
});

// ------------------------------------------------------------
// Memory guard
// ------------------------------------------------------------
let memPressure = false;

setInterval(() => {
    const rssMB = process.memoryUsage().rss / 1048576;
    memPressure = rssMB > MEM_SOFT_LIMIT_MB;
    if (memPressure) queue.sweep(true);
}, 5_000).unref();

app.post('/api/scan', (req, res) => {
    const { url } = req.body || {};

    if (!url || typeof url !== 'string') 
    {
        return res.status(400).json({ error: 'URL is required.' });
    }

    if (url.length > MAX_URL_LENGTH) 
    {
        return res.status(400).json({ error: 'URL is too long.' });
    }

    let cleanUrl;
    try 
    {
        const parsed = new URL(url.trim());

        // the old version also accepted file:, javascript:, ftp: ...
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return res.status(400).json({ error: 'Only http and https URLs are accepted.' });
        }

        parsed.hash = ''; // fragments never reach a server; gives better cache hits
        cleanUrl = parsed.href;
    } 
    
    catch 
    {
        return res.status(400).json({ error: 'Invalid URL format.' });
    }

    if (memPressure) 
    {
        res.set('Retry-After', '5');
        return res.status(503).json({ error: 'Server is low on memory, try again shortly.' });
    }

    const submitted = queue.submit(cleanUrl);

    if (!submitted) 
    {
        res.set('Retry-After', '2');
        return res.status(429).json({ error: 'Server busy, try again shortly.', queue: queue.snapshot() });
    }

    const { job, deduped } = submitted;

    return res.status(202).json({
        status: job.status,
        deduped,
        jobId: job.id,
        target: cleanUrl,
        eventsUrl: `/api/scan/${job.id}/events`,
        pollUrl: `/api/scan/${job.id}`
    });
});

let sseClients = 0;

app.get('/api/scan/:id/events', (req, res) => {
    const job = queue.get(req.params.id);

    if (!job) return res.status(404).json({ error: 'Unknown or expired job.' });
    if (sseClients >= MAX_SSE_CLIENTS) return res.status(503).json({ error: 'Too many live connections.' });

    sseClients++;

    res.status(200).set({
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'   // stop nginx from buffering the stream
    });
    res.flushHeaders();
    res.write('retry: 2000\n\n');

    // On auto-reconnect the browser sends Last-Event-ID, so nothing prints twice.
    const fromSeq = Number(req.get('Last-Event-ID')) || 0;

    let closed = false;
    let unsubscribe = null;

    const heartbeat = setInterval(() => {
        if (!res.writableEnded) res.write(': keep-alive\n\n');
    }, 15_000);

    const cleanup = () => {
        if (closed) return;
        closed = true;
        clearInterval(heartbeat);
        if (unsubscribe) unsubscribe();
        sseClients--;
    };

    const send = ev => {
        if (res.writableEnded) return;

        res.write(`id: ${ev.seq}\nevent: ${ev.type}\ndata: ${JSON.stringify(ev.data)}\n\n`);

        if (ev.type === 'done' || ev.type === 'error') {
            cleanup();
            res.end();
        }
    };

    res.on('close', cleanup);
    unsubscribe = queue.subscribe(job, fromSeq, send);
    if (closed && unsubscribe) unsubscribe();
});

app.get('/api/scan/:id', (req, res) => {
    const job = queue.get(req.params.id);

    if (!job) return res.status(404).json({ error: 'Unknown or expired job.' });

    if (job.status === 'done') {
        return res.json({ status: 'done', jobId: job.id, target: job.url, ...job.result });
    }
    if (job.status === 'error') {
        return res.status(500).json({ status: 'error', jobId: job.id, error: job.error });
    }
    return res.json({ status: job.status, jobId: job.id, target: job.url });
});

app.get('/api/health', (req, res) => {
    const m = process.memoryUsage();
    res.json({
        ok: true,
        queue: queue.snapshot(),
        sseClients,
        memoryMB: { rss: Math.round(m.rss / 1048576), heapUsed: Math.round(m.heapUsed / 1048576) }
    });
});

app.use((err, req, res, next) => {
    res.status(err.status || 400).json({ error: 'Bad request.' });
});

process.on('unhandledRejection', err => console.error('[unhandledRejection]', err));
process.on('uncaughtException', err => console.error('[uncaughtException]', err));

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}  (sandbox concurrency ${SCAN_CONCURRENCY})`);
});
