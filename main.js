console.log("Initiating sequence");

const API_BASE = location.protocol === 'file:' ? 'http://localhost:3000' : '';

const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const TAGS = { info: '[*]', good: '[+]', warn: '[!]', bad: '[-]', none: '   ' };

// so the newest scan is first and older scans pile up underneath it.
let currentBlock = null;
const target = () => currentBlock || term();

// SECURITY: everything printed here can contain attacker-controlled text
// (URLs, page titles, findings). Only textContent is used, never innerHTML.

function term() 
{
    return document.getElementById('terminal');
}

function print(kind, text, extraClass = '') 
{
    const el = document.createElement('div');
    el.className = `line ${kind === 'none' ? 'dim' : kind} ${extraClass}`.trim();

    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.textContent = TAGS[kind] || TAGS.none;

    const body = document.createElement('span');
    body.textContent = text;

    el.append(tag, body);

    const t = target();
    t.insertBefore(el, t.querySelector('.spinner'));

}

function printPlain(text, cls) 
{
    const el = document.createElement('div');
    el.className = `line ${cls}`;
    el.textContent = text;

    const t = target();
    t.insertBefore(el, t.querySelector('.spinner'));
}

const pad = label => label.padEnd(12, ' ');

class Spinner 
{
    constructor() 
    {
        this.el = document.createElement('div');
        this.el.className = 'line info spinner';
        this.text = 'Scanning';
        this.frame = 0;
        this.t0 = Date.now();
        this.timer = null;
    }

    start() 
    {
        target().appendChild(this.el);
        this.render();
        this.timer = setInterval(() => this.render(), 80);
    }

    render() 
    {
        const elapsed = Date.now() - this.t0;
        const dots = '.'.repeat(1 + (Math.floor(elapsed / 350) % 3)).padEnd(3, ' ');
        const spin = SPIN[this.frame++ % SPIN.length];
        this.el.textContent = `[*] ${this.text}${dots} ${spin}  ${(elapsed / 1000).toFixed(1)}s`;
    }

    setText(text) 
    {
        this.text = text;
    }

    stop() 
    {
        clearInterval(this.timer);
        this.el.remove();
    }
}

const HANDLERS = 
{
    queued(d, spinner) 
    {
        spinner.setText(`Queued (position ${d.position})`);
        print('info', `${pad('Queue')}: waiting for a free sandbox, position ${d.position}`);
    },

    started(d, spinner) 
    {
        spinner.setText('Scanning');
    },

    blacklist(d) 
    {
        if (!d.sourcesLoaded) 
        {
            print('warn', `${pad('Threat lists')}: not loaded yet, check skipped`);
            return;
        }

        if (d.matchType === 'Exact URL') 
        {
            print('bad', `${pad('Threat lists')}: exact URL match in ${d.exactSources.join(', ')}`);
        }
        if (d.domainSources && d.domainSources.length) 
        {
            print(d.matchType === 'Exact URL' ? 'bad' : 'warn',
                `${pad('Threat lists')}: host/domain listed in ${d.domainSources.join(', ')}`);
        }
        if (d.matchType === 'None') 
        {
            print('good', `${pad('Threat lists')}: not listed in ${d.sourcesLoaded} lists ` +
                `(${d.totalUrlsLoaded.toLocaleString()} entries checked)`);
        }
        if (d.sourcesLoaded < d.sourcesTotal) 
        {
            print('warn', `${pad('Threat lists')}: ${d.sourcesTotal - d.sourcesLoaded} list(s) not available right now`);
        }
    },

    safebrowsing(d) 
    {
        if (d.error) 
        {
            print('warn', `${pad('SafeBrowse')}: lookup ${d.error}`);
        } 
        else if (d.matched) 
        {
            print('bad', `${pad('SafeBrowse')}: flagged by Google (${d.threats.join(', ')})`);
        } 
        else 
        {
            print('good', `${pad('SafeBrowse')}: no match in Google Safe Browsing`);
        }
    },

    heuristics(d) 
    {
        if (d.error) 
        {
            print('warn', `${pad('Heuristics')}: ${d.error}`);
            return;
        }

        print(d.suspicious ? 'warn' : 'good',
            `${pad('Heuristics')}: risk score ${d.riskScore} (${d.suspicious ? 'suspicious' : 'ok'})`);

        for (const w of d.warnings || []) 
        {
            print('none', `${' '.repeat(12)}  - ${w}`, 'warn');
        }
    },

    sandbox_start(d, spinner) 
    {
        spinner.setText('Scanning (sandbox)');
        print('info', `${pad('Sandbox')}: opening page in an isolated headless browser`);
    },

    sandbox(d) 
    {
        if (d.skipped) 
        {
            print('info', `${pad('Sandbox')}: skipped (${d.reason})`);
            return;
        }

        if (!d.working) 
        {
            print('bad', `${pad('Sandbox')}: failed (${d.error || 'unknown error'})`);
            return;
        }

        const level = d.suspicionScore >= 70 ? 'bad' : d.suspicionScore >= 40 ? 'warn' : 'good';
        print(level, `${pad('Sandbox')}: behavior score ${d.suspicionScore}/100 (${d.riskLevel})`);

        if (d.navigationError || d.timedOut) 
        {
            print('warn', `${pad('Sandbox')}: page did not finish loading in time`);
        }

        if (d.finalUrl && d.finalUrl !== d.url) 
        {
            print('info', `${pad('Final URL')}: ${d.finalUrl}`);
        }

        const s = d.statistics || {};
        print('none', `${pad('Activity')}: ${s.requests || 0} requests, ${s.redirects || 0} redirects, ` +
            `${s.frames || 0} frames, ${s.popups || 0} popups, ${s.downloads || 0} downloads`);

        for (const f of d.findings || []) {
            const k = f.severity === 'high' ? 'bad' : f.severity === 'medium' ? 'warn' : 'none';
            print(k, `${' '.repeat(12)}  - [${f.severity}] ${f.type}: ${f.details}`);
        }
    },

    verdict(d) 
    {
        const map = 
        {
            clean: ['good', 'CLEAN'],
            suspicious: ['warn', 'SUSPICIOUS'],
            malicious: ['bad', 'MALICIOUS'],
            unverified: ['warn', 'UNVERIFIED (could not be fully analyzed)']
        };
        const [kind, label] = map[d.verdict] || ['warn', String(d.verdict).toUpperCase()];

        printPlain('', 'dim');
        print(kind, `Verdict: ${label}`, 'verdict');

        for (const r of d.reasons || []) 
        {
            print('none', `${' '.repeat(3)}- ${r}`);
        }
    },

    done(d) 
    {
        const queued = d.queueMs > 500 ? `, waited ${(d.queueMs / 1000).toFixed(1)}s in queue` : '';
        print('info', `Scan completed in ${(d.totalMs / 1000).toFixed(1)}s${queued}`);
    },

    error(d) 
    {
        print('bad', `Scan failed: ${d.message}`);
    }
};


function streamEvents(jobId) 
{
    return new Promise(resolve => 
        {
        const es = new EventSource(`${API_BASE}/api/scan/${jobId}/events`);
        let finished = false;

        const end = () => {
            if (finished) return;
            finished = true;
            clearTimeout(guard);
            es.close();
            resolve();
        };

        // safety net: never spin forever
        const guard = setTimeout(() => {
            print('bad', 'Timed out waiting for the scan to finish.');
            end();
        }, 90_000);

        for (const type of Object.keys(HANDLERS)) {
            es.addEventListener(type, e => {
                let data;
                try { data = JSON.parse(e.data); } catch { return; }

                HANDLERS[type](data, currentSpinner);
                if (type === 'done' || type === 'error') end();
            });
        }

        es.onerror = () => {
            if (es.readyState === EventSource.CLOSED) {
                print('bad', 'Connection to the scan server was lost.');
                end();
            }
        };
    });
}

let currentSpinner = null;

async function runScan(rawInput) 
{
    let url = rawInput.trim();
    let assumedScheme = false;

    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) 
    {
        url = 'https://' + url;
        assumedScheme = true;
    }

    document.body.classList.add('active');

    const block = document.createElement('div');
    block.className = 'scan-block';
    term().insertBefore(block, term().firstChild);
    currentBlock = block;

    printPlain(`spectre> scan ${url}`, 'prompt');
    if (assumedScheme) print('info', 'No scheme given, assuming https://');

    currentSpinner = new Spinner();
    currentSpinner.start();

    try
    {
        const res = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        const body = await res.json().catch(() => ({}));

        if (res.status === 429 || res.status === 503) 
        {
            print('bad', 'Server is busy right now. Please try again in a few seconds.');
            return;
        }
        if (!res.ok && res.status !== 202) 
        {
            print('bad', body.error || `Request failed (HTTP ${res.status})`);
            return;
        }

        print('info', `${pad('Target')}: ${body.target}`);
        if (body.deduped) print('info', 'Reusing an identical scan from the last few minutes');

        await streamEvents(body.jobId);
    } 
    catch (error) 
    {
        print('bad', `Request failed: ${error.message}`);
    } finally 
    {
        currentSpinner.stop();
        currentSpinner = null;
        currentBlock = null;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const submitBtn = document.getElementById('submitBtn');
    const myInput = document.getElementById('myInput');

    async function submit() 
    {
        const inputUrl = myInput.value.trim();

        if (!inputUrl) 
        {
            alert('Please enter a URL');
            return;
        }

        submitBtn.disabled = true;
        myInput.disabled = true;

        try 
        {
            await runScan(inputUrl);
        } 
        finally 
        {
            submitBtn.disabled = false;
            myInput.disabled = false;
            myInput.focus();
        }
    }

    submitBtn.addEventListener('click', submit);
    myInput.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !submitBtn.disabled) submit();
    });
});
