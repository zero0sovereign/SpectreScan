// Install:
//   npm install express playwright
//   npx playwright install chromium

const express = require("express");
const { chromium } = require("playwright");
const os = require("os");

const app = express();

app.use(express.json({ limit: "16kb" }));

//CONFIGURATION
// Everything below can be overridden with environment variables.
const PORT = Number(process.env.PORT || 3000);   // host's VM_Check.js calls :4000. This is done using port forwading in VM settings where host_port: 4000, guest_port:

// Sized for a VM where Chromium may use ~1-1.5 GB:
// 3 pages at once ~ 3 x 150-300 MB + ~120 MB browser process.
const WORKER_COUNT = Number(process.env.WORKERS || 3);
const MAX_QUEUE_SIZE = Number(process.env.MAX_QUEUE || 10);

const NAVIGATION_TIMEOUT = Number(process.env.NAV_TIMEOUT || 3_000);
const OBSERVATION_TIME = Number(process.env.OBSERVE_MS || 1_500); // max settle wait
const MIN_OBSERVATION = 800;    // always watch at least this long
const HARD_DEADLINE = Number(process.env.HARD_DEADLINE || 8_000); // kill a scan after this

// "context" = one shared Chromium, isolated context per scan (fast, low RAM)
// "browser" = new Chromium per scan (slowest, strongest isolation)
const ISOLATION = process.env.ISOLATION === "browser" ? "browser" : "context";
const RECYCLE_AFTER = Number(process.env.RECYCLE_AFTER || 150); // restart Chromium after N scans
const MIN_FREE_MB = Number(process.env.MIN_FREE_MB || 150);     // wait if the VM is this low on RAM
const BLOCK_HEAVY = process.env.BLOCK_HEAVY !== "0";            // skip images/media/fonts

const MAX_REQUESTS = 1000;
const MAX_RESPONSES = 1000;
const MAX_FRAMES = 300;
const MAX_DOWNLOADS = 100;
const MAX_POPUPS = 100;
const MAX_REDIRECTS = 100;
const MAX_CONSOLE_MESSAGES = 200;
const MAX_PAGE_ERRORS = 100;

const MAX_SCORE = 100;

// QUEUE
const scanQueue = [];
const waiters = [];   // idle workers waiting for a job

let jobCounter = 0;

function createJobId() 
{
    jobCounter += 1;
    return `${Date.now()}-${jobCounter}`;
}

function enqueue(targetUrl) 
{
    return new Promise((resolve, reject) => {
        if (scanQueue.length >= MAX_QUEUE_SIZE) 
        {
            reject(new Error("Scan queue is full"));
            return;
        }

        const job = 
        {
            id: createJobId(),
            targetUrl,
            createdAt: Date.now(),
            resolve,
            reject
        };

        // hand the job straight to an idle worker, otherwise queue it
        const waiter = waiters.shift();

        if (waiter) 
        {
            waiter(job);
        } 
        
        else 
        {
            scanQueue.push(job);
        }
    });
}

function nextJob() 
{
    if (scanQueue.length > 0) 
    {
        return Promise.resolve(scanQueue.shift());
    }

    return new Promise(resolve => waiters.push(resolve));
}

function sleep(ms) 
{
    return new Promise(resolve => setTimeout(resolve, ms));
}

// SAFE ARRAY PUSH
function pushLimited(array, item, max) {
    if (array.length < max) {
        array.push(item);
    }
}


// URL HELPERS
function getHostname(url) 
{
    try 
    {
        return new URL(url).hostname.toLowerCase();
    } 
    
    catch 
    {
        return "";
    }
}

function getOrigin(url) 
{
    try 
    {
        return new URL(url).origin;
    } 
    
    catch 
    {
        return "";
    }
}

function isValidTargetUrl(url) 
{
    try 
    {
        const parsed = new URL(url);

        return (
            parsed.protocol === "http:" ||
            parsed.protocol === "https:"
        );
    } 
    
    catch 
    {
        return false;
    }
}

function isPotentiallyExecutableFilename(filename) 
{
    if (!filename) return false;

    const lower = filename.toLowerCase();

    const executableExtensions = [
        ".exe",
        ".msi",
        ".scr",
        ".com",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".jar",
        ".hta",
        ".dll",
        ".apk",
        ".dmg",
        ".pkg",
        ".deb",
        ".rpm"
    ];

    return executableExtensions.some(ext =>
        lower.endsWith(ext)
    );
}


// BEHAVIORAL SCORING
// These are heuristic indicators, NOT proof that a website is malicious
// The host can combine this result with its other modules.

function analyzeBehavior(telemetry) 
{
    let score = 0;

    const findings = [];

    function addFinding({
        type,
        severity,
        points,
        details,
        evidence = null
    }) {
        score += points;

        findings.push({
            type,
            severity,
            score: points,
            details,
            evidence
        });
    }

   
    // Downloads
    if (telemetry.downloads.length > 0) 
    {
        addFinding({
            type: "unexpected_download",
            severity: "high",
            points: 25,
            details:
                `${telemetry.downloads.length} download(s) ` +
                "were triggered during page execution.",
            evidence: telemetry.downloads
        });

        const executableDownloads =
            telemetry.downloads.filter(download =>
                isPotentiallyExecutableFilename(
                    download.suggestedFilename
                )
            );

        if (executableDownloads.length > 0) 
        {
            addFinding({
                type: "executable_download",
                severity: "high",
                points: 30,
                details:
                    `${executableDownloads.length} potentially ` +
                    "executable file(s) were downloaded.",
                evidence: executableDownloads
            });
        }
    }

    // Hidden iframes
    if (telemetry.dom.hiddenIframeCount > 0) {
        const count = telemetry.dom.hiddenIframeCount;

        const points = Math.min(20, 5 + count * 3);

        addFinding({
            type: "hidden_iframe",
            severity: count >= 3 ? "medium" : "low",
            points,
            details:
                `${count} hidden iframe(s) detected.`,
            evidence: 
            {
                hiddenIframeCount: count,
                iframeCount: telemetry.dom.iframeCount
            }
        });
    }

    // Excessive iframe usage
    if (telemetry.dom.iframeCount >= 10)
    {
        addFinding({
            type: "excessive_iframes",
            severity: "medium",
            points: 8,
            details:
                `${telemetry.dom.iframeCount} iframe(s) detected.`,
            evidence: 
            {
                iframeCount: telemetry.dom.iframeCount
            }
        });
    }


    // Redirect chain
    const redirectCount =
        Math.max(
            0,
            telemetry.navigation.redirects.length - 1
        );

    if (redirectCount >= 3) 
    {
        const points = Math.min(
            15,
            5 + (redirectCount - 3) * 2
        );

        addFinding({
            type: "redirect_chain",
            severity: "medium",
            points,
            details:
                `${redirectCount} main-frame redirect(s) detected.`,
            evidence: {
                chain: telemetry.navigation.redirects
            }
        });
    }

    // Popups / new tabs
    if (telemetry.popups.length > 0) {
        const count = telemetry.popups.length;

        const points = Math.min(15, 5 + count * 2);

        addFinding({
            type: "popup_or_new_tab",
            severity: count >= 3 ? "medium" : "low",
            points,
            details:
                `${count} popup/new tab event(s) detected.`,
            evidence: telemetry.popups
        });
    }

    
    // Excessive external scripts
    if (telemetry.dom.externalScriptCount >= 20) 
    {
        addFinding({
            type: "excessive_external_scripts",
            severity: "low",
            points: 5,
            details:
                `${telemetry.dom.externalScriptCount} external ` +
                "scripts detected.",
            evidence: 
            {
                externalScriptCount:
                    telemetry.dom.externalScriptCount
            }
        });
    }

    // Large number of network requests
    if (telemetry.requests.length >= 200)
    {
        addFinding({
            type: "high_network_activity",
            severity: "low",
            points: 5,
            details:
                `${telemetry.requests.length} network requests ` +
                "observed during scanning.",
            evidence: 
            {
                requestCount: telemetry.requests.length
            }
        });
    }

    // Password form
    if (telemetry.dom.passwordFieldCount > 0) 
    {
        addFinding({
            type: "password_form",
            severity: "low",
            points: 3,
            details:
                "A password input was detected on the page.",
            evidence: 
            {
                passwordFieldCount:
                    telemetry.dom.passwordFieldCount
            }
        });
    }

    // Dialog abuse
    if (telemetry.dialogs.length >= 3)
    {
        addFinding({
            type: "excessive_dialogs",
            severity: "medium",
            points: 8,
            details:
                `${telemetry.dialogs.length} JavaScript ` +
                "dialog(s) were triggered.",
            evidence: telemetry.dialogs
        });
    }

    // Browser notification requests
    if (telemetry.permissions.notificationRequests > 0) 
    {
        addFinding({
            type: "notification_permission_request",
            severity: "low",
            points: 4,
            details:
                "The page attempted to request browser " +
                "notification permission.",
            evidence: 
            {
                count:
                    telemetry.permissions.notificationRequests
            }
        });
    }

    
    // Suspicious page text
    if (telemetry.dom.suspiciousText.length > 0) 
    {
        addFinding({
            type: "suspicious_security_text",
            severity: "medium",
            points: 12,
            details:
                "Page contained text resembling fake security " +
                "warnings or urgent malware/download prompts.",
            evidence: telemetry.dom.suspiciousText
        });
    }

    // Final score
    score = Math.min(MAX_SCORE, score);

    let riskLevel;

    if (score < 20) 
    {
        riskLevel = "low";
    } 
    
    else if (score < 50) 
    {
        riskLevel = "suspicious";
    } 
    
    else if (score < 75) 
    {
        riskLevel = "high";
    } else {
        riskLevel = "very_high";
    }

    return {
        suspicionScore: score,
        riskLevel,
        findings
    };
}

// ============================================================
// BROWSER POOL
// ============================================================
//
// One shared Chromium process, a fresh BrowserContext per scan.
// A context has its own cookies, storage, cache, permissions and
// service workers, and all telemetry lives in a per-scan object, so
// two scans cannot write into each other's results.
//
// The only real shared risk is a browser crash, which would kill
// every in-flight page. That is handled by:
//   - detecting "disconnected" and launching a fresh browser
//   - retrying a crashed scan once (see worker)
//   - recycling the browser every RECYCLE_AFTER scans (leak control)
//   - HARD_DEADLINE so one bad page cannot hold a slot forever

const BROWSER_ARGS = [
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-software-rasterizer",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-sync",
    "--no-first-run",
    "--mute-audio",
    "--js-flags=--max-old-space-size=192"   // cap each renderer's JS heap
];

// Needed when running as root inside a container.
if (process.env.NO_SANDBOX === "1") 
{
    BROWSER_ARGS.push("--no-sandbox");
}

let current = null;

function launchEntry() 
{
    const entry = {
        active: 0,
        used: 0,
        retiring: false,
        dead: false
    };

    entry.promise = chromium.launch({
        headless: true,
        args: BROWSER_ARGS
    });

    entry.promise
        .then(browser => {
            browser.on("disconnected", () => {
                entry.dead = true;

                if (current === entry) {
                    current = null;
                }
            });
        })
        .catch(() => {
            entry.dead = true;

            if (current === entry) {
                current = null;
            }
        });

    return entry;
}

function maybeClose(entry) 
{
    if (entry.retiring && entry.active === 0) 
    {
        entry.promise
            .then(browser => browser.close())
            .catch(() => {});
    }
}

async function acquireBrowser()
{
    let entry;

    if (ISOLATION === "browser") 
    {
        entry = launchEntry();
        entry.retiring = true;   // closed as soon as this scan is done
    } 
    
    else 
    {
        if (
            !current ||
            current.dead ||
            current.used >= RECYCLE_AFTER
        ) {
            const old = current;

            current = launchEntry();

            if (old) 
            {
                old.retiring = true;
                maybeClose(old);
            }
        }

        entry = current;
    }

    entry.used += 1;
    entry.active += 1;

    try 
    {
        const browser = await entry.promise;
        return { entry, browser };
    } 
    
    catch (error) 
    {
        entry.active -= 1;
        throw error;
    }
}

function releaseBrowser(entry) 
{
    entry.active -= 1;
    maybeClose(entry);
}

// If the VM is nearly out of RAM, wait a moment instead of piling on
// another page (which is how the Linux OOM killer ends up shooting Chromium).
async function waitForMemory() 
{
    const start = Date.now();

    while (
        os.freemem() / 1048576 < MIN_FREE_MB &&
        Date.now() - start < 3000
    ) {
        await sleep(200);
    }
}

// Warm up so the first scan doesn't pay the launch cost.
if (ISOLATION === "context") 
{
    current = launchEntry();
}

// ============================================================
// PLAYWRIGHT SCANNER
// ============================================================

async function scanWithPlaywright(targetUrl, workerId, jobId) 
{
    const startTime = Date.now();

    let browser = null;
    let context = null;
    let lease = null;
    let killTimer = null;
    let timedOut = false;

    const telemetry = {
        initialUrl: targetUrl,
        finalUrl: null,

        navigation: {
            redirects: [],
            mainFrameNavigations: []
        },

        requests: [],
        responses: [],

        frames: [],
        downloads: [],
        popups: [],

        dialogs: [],
        console: [],
        pageErrors: [],

        permissions: {
            notificationRequests: 0
        },

        dom: {
            iframeCount: 0,
            hiddenIframeCount: 0,
            scriptCount: 0,
            externalScriptCount: 0,
            formCount: 0,
            passwordFieldCount: 0,
            hiddenElementCount: 0,
            suspiciousText: []
        },

        errors: [],

        statistics: {},

        timing: {}
    };

    try 
    {
        console.log(
            `[WORKER ${workerId}] [${jobId}] ` +
            `Launching Chromium for ${targetUrl}`
        );

        // Hard stop: closing the context makes every pending await throw,
        // which frees the worker slot even if the page is stuck.
        killTimer = setTimeout(() => {
            timedOut = true;

            if (context) {
                context.close().catch(() => {});
            }
        }, HARD_DEADLINE);

        await waitForMemory();

        lease = await acquireBrowser();
        browser = lease.browser;

        if (timedOut) 
        {
            throw new Error("Scan exceeded hard deadline");
        }

        context = await browser.newContext({
            acceptDownloads: true,
            ignoreHTTPSErrors: true,   // phishing sites often have broken certs
            serviceWorkers: "block"
        });

        // Don't download bytes the analysis never uses. Request events
        // still fire, so request counts in the telemetry are unchanged.
        if (BLOCK_HEAVY) 
        {
            await context.route("**/*", route => {
                const type = route.request().resourceType();

                if (
                    type === "image" ||
                    type === "media" ||
                    type === "font"
                ) {
                    return route.abort();
                }

                return route.continue();
            });
        }

        const page = await context.newPage();

        // ====================================================
        // NETWORK REQUESTS
        // ====================================================

        page.on("request", request => {
            pushLimited(
                telemetry.requests,
                {
                    url: request.url(),
                    method: request.method(),
                    resourceType: request.resourceType(),
                    isNavigationRequest:
                        request.isNavigationRequest(),
                    timestamp: Date.now()
                },
                MAX_REQUESTS
            );
        });

        // ====================================================
        // NETWORK RESPONSES
        // ====================================================

        page.on("response", response => {
            const request = response.request();

            pushLimited(
                telemetry.responses,
                {
                    url: response.url(),
                    status: response.status(),
                    contentType:
                        response.headers()["content-type"] ||
                        null,
                    resourceType:
                        request.resourceType(),
                    timestamp: Date.now()
                },
                MAX_RESPONSES
            );
        });

        // ====================================================
        // NAVIGATION
        // ====================================================

        page.on("framenavigated", frame => {
            const url = frame.url();

            if (!url) return;

            if (frame === page.mainFrame()) 
            {
                telemetry.navigation.redirects.push(url);

                pushLimited(
                    telemetry.navigation.mainFrameNavigations,
                    {
                        url,
                        timestamp: Date.now()
                    },
                    MAX_REDIRECTS
                );
            } 
            
            else 
            {
                pushLimited(
                    telemetry.frames,
                    {
                        event: "navigated",
                        url,
                        timestamp: Date.now()
                    },
                    MAX_FRAMES
                );
            }
        });

        // ====================================================
        // FRAME ATTACHMENT
        // ====================================================

        page.on("frameattached", frame => {
            pushLimited(
                telemetry.frames,
                {
                    event: "attached",
                    url: frame.url(),
                    timestamp: Date.now()
                },
                MAX_FRAMES
            );
        });

        page.on("framedetached", frame => {
            pushLimited(
                telemetry.frames,
                {
                    event: "detached",
                    url: frame.url(),
                    timestamp: Date.now()
                },
                MAX_FRAMES
            );
        });

        // ====================================================
        // DOWNLOADS
        // ====================================================

        page.on("download", async download => {
            let failure = null;

            try {
                failure = await download.failure();
            } catch {}

            pushLimited(
                telemetry.downloads,
                {
                    url: download.url(),
                    suggestedFilename:
                        download.suggestedFilename(),
                    failure,
                    timestamp: Date.now()
                },
                MAX_DOWNLOADS
            );
        });

        // ====================================================
        // POPUPS / NEW TABS
        // ====================================================

        context.on("page", popup => {
            pushLimited(
                telemetry.popups,
                {
                    url: popup.url(),
                    timestamp: Date.now()
                },
                MAX_POPUPS
            );
        });

        // ====================================================
        // JAVASCRIPT CONSOLE
        // ====================================================

        page.on("console", message => {
            pushLimited(
                telemetry.console,
                {
                    type: message.type(),
                    text: message.text(),
                    timestamp: Date.now()
                },
                MAX_CONSOLE_MESSAGES
            );
        });

        // ====================================================
        // PAGE ERRORS
        // ====================================================

        page.on("pageerror", error => {
            pushLimited(
                telemetry.pageErrors,
                {
                    message: error.message,
                    timestamp: Date.now()
                },
                MAX_PAGE_ERRORS
            );
        });

        // ====================================================
        // DIALOGS
        // ====================================================

        page.on("dialog", async dialog => {
            pushLimited(
                telemetry.dialogs,
                {
                    type: dialog.type(),
                    message: dialog.message(),
                    timestamp: Date.now()
                },
                100
            );

            // Dismiss dialogs so they cannot block the worker.
            try 
            {
                await dialog.dismiss();
            } 
            catch {}
        });

        // ====================================================
        // NOTIFICATION PERMISSION OBSERVATION
        // ====================================================

        page.on("request", request => {
            const url = request.url();

            // This is not a perfect permission detector.
            // Actual permission behavior is inspected separately
            // through DOM/JS evaluation below.
            if (url.includes("notification")) {
                // Don't count this directly as a permission request.
            }
        });

        // ====================================================
        // NAVIGATE
        // ====================================================

        try 
        {
            await page.goto(targetUrl, {
                waitUntil: "domcontentloaded",
                timeout: NAVIGATION_TIMEOUT
            });
        } 
        
        catch (error) 
        {
            // Chromium died (not a normal slow/failed page): abort this
            // attempt so the worker can retry once on a fresh browser.
            if (
                !timedOut &&
                /has been closed|disconnected|crash/i.test(error.message)
            ) {
                throw error;
            }

            telemetry.errors.push({
                stage: "navigation",
                message: error.message
            });
        }

        // ====================================================
        // BOUNDED OBSERVATION PERIOD
        // ====================================================

        // Wait for the page to go quiet (up to OBSERVATION_TIME), but always
        // watch for at least MIN_OBSERVATION so redirect / popup / download
        // timers get a chance to fire.
        const observeStart = Date.now();

        await page
            .waitForLoadState("networkidle", {
                timeout: OBSERVATION_TIME
            })
            .catch(() => {});

        const spent = Date.now() - observeStart;

        if (spent < MIN_OBSERVATION) 
        {
            await page.waitForTimeout(MIN_OBSERVATION - spent);
        }

        // ====================================================
        // DOM ANALYSIS
        // ====================================================

        try 
        {
            telemetry.dom = await page.evaluate(() => {
                const all =
                    Array.from(
                        document.querySelectorAll("*")
                    );

                const iframes =
                    Array.from(
                        document.querySelectorAll("iframe")
                    );

                const scripts =
                    Array.from(
                        document.querySelectorAll("script")
                    );

                const forms =
                    Array.from(
                        document.querySelectorAll("form")
                    );

                function isHidden(element) 
                {
                    const style =
                        window.getComputedStyle(element);

                    const rect =
                        element.getBoundingClientRect();

                    return (
                        style.display === "none" ||
                        style.visibility === "hidden" ||
                        style.opacity === "0" ||
                        rect.width === 0 ||
                        rect.height === 0
                    );
                }

                let hiddenIframeCount = 0;
                let hiddenElementCount = 0;

                for (const iframe of iframes) 
                {
                    if (isHidden(iframe)) 
                    {
                        hiddenIframeCount++;
                    }
                }

                for (const element of all) 
                {
                    if (isHidden(element)) 
                    {
                        hiddenElementCount++;
                    }
                }

                const externalScriptCount =
                    scripts.filter(
                        script => Boolean(script.src)
                    ).length;

                const passwordFieldCount =
                    document.querySelectorAll(
                        'input[type="password"]'
                    ).length;

                const bodyText =
                    document.body
                        ? document.body.innerText.toLowerCase()
                        : "";

                const suspiciousPatterns = [
                    "your computer is infected",
                    "your device is infected",
                    "virus detected",
                    "malware detected",
                    "security warning",
                    "critical security alert",
                    "download now",
                    "update your browser",
                    "your browser is out of date",
                    "call support",
                    "call microsoft",
                    "call apple"
                ];

                const suspiciousText =
                    suspiciousPatterns.filter(
                        pattern =>
                            bodyText.includes(pattern)
                    );

                return {
                    iframeCount: iframes.length,
                    hiddenIframeCount,
                    scriptCount: scripts.length,
                    externalScriptCount,
                    formCount: forms.length,
                    passwordFieldCount,
                    hiddenElementCount,
                    suspiciousText
                };
            });
        } 
        
        catch (error) 
        {
            telemetry.errors.push({
                stage: "dom-analysis",
                message: error.message
            });
        }

        // ====================================================
        // NOTIFICATION PERMISSION CHECK
        // ====================================================

        try 
        {
            telemetry.permissions =
                await page.evaluate(() => {
                    let notificationRequests = 0;

                    // This detects the presence of the Notification
                    // API and its current permission state.
                    // It intentionally does NOT grant permission.
                    const notificationAvailable =
                        typeof Notification !== "undefined";

                    return {
                        notificationRequests,
                        notificationApiAvailable:
                            notificationAvailable,
                        notificationPermission:
                            notificationAvailable
                                ? Notification.permission
                                : "unavailable"
                    };
                });
        } 
        
        catch 
        {
            telemetry.permissions = {
                notificationRequests: 0
            };
        }

        // ====================================================
        // FINAL URL
        // ====================================================

        telemetry.finalUrl = page.url();

        // ====================================================
        // STATISTICS
        // ====================================================

        telemetry.statistics = {
            requests: telemetry.requests.length,
            responses: telemetry.responses.length,
            redirects:
                Math.max(
                    0,
                    telemetry.navigation.redirects.length - 1
                ),
            frames: telemetry.frames.length,
            downloads: telemetry.downloads.length,
            popups: telemetry.popups.length,
            dialogs: telemetry.dialogs.length,
            consoleMessages: telemetry.console.length,
            pageErrors: telemetry.pageErrors.length
        };

        telemetry.timing = {
            durationMs: Date.now() - startTime
        };

        // ====================================================
        // ANALYZE BEHAVIOR
        // ====================================================

        const analysis = analyzeBehavior(telemetry);

        return {
            success: true,

            workerId,
            jobId,

            target: targetUrl,
            finalUrl: telemetry.finalUrl,

            suspicionScore:
                analysis.suspicionScore,

            riskLevel:
                analysis.riskLevel,

            findings:
                analysis.findings,

            statistics:
                telemetry.statistics,

            // Lets the host tell "looked clean" from "never finished loading".
            navigationError:
                (telemetry.errors.find(
                    e => e.stage === "navigation"
                ) || {}).message || null,

            timedOut,

            telemetry
        };

    } 
    
    catch (error) 
    {
        return {
            success: false,

            workerId,
            jobId,

            target: targetUrl,

            suspicionScore: 0,

            riskLevel: "unknown",

            findings: [],

            error: timedOut
                ? "Scan exceeded hard deadline"
                : error.message,

            timedOut,

            // browser died under us (not our own timeout) -> worth one retry
            retryable:
                !timedOut &&
                /closed|disconnected|crash/i.test(error.message),

            telemetry
        };

    } 
    
    finally 
    {
        // ====================================================
        // ALWAYS CLEAN UP
        // ====================================================

        clearTimeout(killTimer);

        try 
        {
            if (context) {
                await context.close();
            }
        } 
        
        catch {}

        if (lease) {
            releaseBrowser(lease.entry);
        }
    }
}

// ============================================================
// WORKER
// ============================================================

async function worker(workerId) 
{
    console.log(`[WORKER ${workerId}] Started`);

    while (true) 
    {
        const job = await nextJob();

        console.log(
            `[WORKER ${workerId}] ` +
            `Picked ${job.id} | ${job.targetUrl} | ` +
            `remaining=${scanQueue.length}`
        );

        try 
        {
            let result = await scanWithPlaywright(
                job.targetUrl,
                workerId,
                job.id
            );

            // If Chromium itself crashed mid-scan, retry ONCE on a fresh
            // browser instead of returning wrong/empty data.
            if (!result.success && result.retryable) 
            {
                console.warn(
                    `[WORKER ${workerId}] [${job.id}] ` +
                    "Browser crashed, retrying once"
                );

                result = await scanWithPlaywright(
                    job.targetUrl,
                    workerId,
                    job.id
                );
            }

            job.resolve(result);
        } 
        
        catch (error) 
        {
            job.resolve({
                success: false,
                jobId: job.id,
                target: job.targetUrl,
                suspicionScore: 0,
                riskLevel: "unknown",
                findings: [],
                error: error.message
            });
        }
    }
}

// ============================================================
// START WORKERS
// ============================================================

function startWorkers() 
{
    for (let i = 1; i <= WORKER_COUNT; i++) {
        worker(i).catch(error => {
            console.error(
                `[WORKER ${i}] Fatal worker error:`,
                error
            );
        });
    }
}

// ============================================================
// SCAN API
// ============================================================

app.post("/scan", async (req, res) => {
    const { targetUrl } = req.body || {};

    // --------------------------------------------------------
    // Validate input
    // --------------------------------------------------------

    if (
        !targetUrl ||
        typeof targetUrl !== "string"
    ) {
        return res.status(400).json({
            status: "error",
            error: "targetUrl is required"
        });
    }

    if (!isValidTargetUrl(targetUrl)) {
        return res.status(400).json({
            status: "error",
            error:
                "Only HTTP and HTTPS URLs are accepted"
        });
    }

    // --------------------------------------------------------
    // Backpressure
    // --------------------------------------------------------

    if (scanQueue.length >= MAX_QUEUE_SIZE) 
    {
        console.warn(
            `[QUEUE] FULL - rejected ${targetUrl}`
        );

        return res.status(429).json({
            status: "rejected",
            error: "Scan queue is full",
            queueSize: scanQueue.length,
            maxQueueSize: MAX_QUEUE_SIZE
        });
    }

    // --------------------------------------------------------
    // Queue job
    // --------------------------------------------------------

    try 
    {
        console.log(
            `[API] Queuing scan: ${targetUrl}`
        );

        const result = await enqueue(targetUrl);

        // Full telemetry is large. Send it only on request (?full=1).
        const { telemetry, ...slim } = result;

        return res.json({
            status: "completed",
            target: targetUrl,
            result: req.query.full === "1" ? result : slim
        });

    } 
    
    catch (error) 
    {
        return res.status(503).json({
            status: "error",
            target: targetUrl,
            error: error.message
        });
    }
});

// ============================================================
// STATUS API
// ============================================================

app.get("/status", (req, res) => {
    return res.json({
        status: "running",

        queue: {
            waiting: scanQueue.length,
            capacity: MAX_QUEUE_SIZE
        },

        workers: {
            count: WORKER_COUNT,
            idle: waiters.length
        },

        browser: {
            isolation: ISOLATION,
            scansOnCurrentBrowser: current ? current.used : 0,
            recycleAfter: RECYCLE_AFTER
        },

        memory: {
            vmFreeMB: Math.round(os.freemem() / 1048576),
            nodeRssMB: Math.round(
                process.memoryUsage().rss / 1048576
            )
        },

        configuration: {
            navigationTimeoutMs:
                NAVIGATION_TIMEOUT,

            observationTimeMs:
                OBSERVATION_TIME
        }
    });
});

// ============================================================
// GLOBAL ERROR HANDLERS
// ============================================================

process.on("uncaughtException", error => {
    console.error(
        "[PROCESS] Uncaught exception:",
        error
    );
});

process.on("unhandledRejection", error => {
    console.error(
        "[PROCESS] Unhandled rejection:",
        error
    );
});

// ============================================================
// START SERVER
// ============================================================

startWorkers();

app.listen(PORT, "0.0.0.0", () => {
    console.log("");
    console.log("==============================================");
    console.log("       VM WEBSITE BEHAVIOR SANDBOX");
    console.log("==============================================");
    console.log(`Port             : ${PORT}`);
    console.log(`Workers          : ${WORKER_COUNT}`);
    console.log(`Queue capacity   : ${MAX_QUEUE_SIZE}`);
    console.log(`Navigation limit : ${NAVIGATION_TIMEOUT} ms`);
    console.log(`Observation      : ${OBSERVATION_TIME} ms (min ${MIN_OBSERVATION})`);
    console.log(`Hard deadline    : ${HARD_DEADLINE} ms`);
    console.log(`Isolation        : ${ISOLATION}`);
    console.log("==============================================");
    console.log("[VM] Server ready");
});
