const VM_URL = process.env.VM_URL || 'http://localhost:4000/scan';
const HARD_TIMEOUT_MS = Number(process.env.VM_TIMEOUT_MS || 12_000); // VM kills scans at 8 s
const MAX_FINDINGS = 40;
const MAX_EVIDENCE_CHARS = 1500;

function trimFinding(f) 
{
    const out = { type: f.type, severity: f.severity, score: f.score, details: f.details };

    if (f.evidence != null) 
    {
        const text = JSON.stringify(f.evidence);
        if (text.length <= MAX_EVIDENCE_CHARS) out.evidence = f.evidence;
        else out.evidenceTruncated = true;
    }
    return out;
}

async function vmSandboxCheck(url) 
{
    try 
    {
        const response = await fetch(VM_URL, 
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetUrl: url }),
            signal: AbortSignal.timeout(HARD_TIMEOUT_MS)
        });

        if (!response.ok) 
        {
            throw new Error(`VM responded with HTTP ${response.status}`);
        }

        const data = await response.json();
        const r = data.result || {};

        return {
            working: r.success !== false,
            url,
            finalUrl: r.finalUrl || url,
            suspicionScore: r.suspicionScore ?? 0,
            riskLevel: r.riskLevel || 'unknown',
            findings: (r.findings || []).slice(0, MAX_FINDINGS).map(trimFinding),
            statistics: r.statistics || {},
            navigationError: r.navigationError || null,
            timedOut: Boolean(r.timedOut),
            error: r.error
        };
    } 
    
    catch (error) 
    {
        return {
            working: false,
            url,
            error: error.name === 'TimeoutError' ? 'VM scan timed out' : error.message
        };
    }
}

module.exports = vmSandboxCheck;
