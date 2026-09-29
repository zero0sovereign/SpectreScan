// vm_server.js
//
// VM-only behavioral website scanner.
//
// Flow:
//   Host -> POST /scan
//        -> bounded queue
//        -> 4 parallel workers
//        -> Playwright/Chromium
//        -> behavioral analysis
//        -> suspicion score + findings
//        -> JSON response to Host
//
// Install:
//   npm install express playwright
//   npx playwright install chromium
//
// IMPORTANT:
// The VM/container/network isolation is the actual security boundary.
// Do not expose this scanner directly to the public Internet.

const express = require("express");
const { chromium } = require("playwright");

const app = express();

app.use(express.json({ limit: "16kb" }));

// ============================================================
// CONFIG
// ============================================================

const PORT = 3000;

const WORKER_COUNT = 4;
const MAX_QUEUE_SIZE = 50;

const NAVIGATION_TIMEOUT = 15_000;
const OBSERVATION_TIME = 5_000;

const MAX_REQUESTS = 1000;
const MAX_RESPONSES = 1000;
const MAX_FRAMES = 300;
const MAX_DOWNLOADS = 100;
const MAX_POPUPS = 100;
const MAX_REDIRECTS = 100;
const MAX_CONSOLE_MESSAGES = 200;
const MAX_PAGE_ERRORS = 100;

const MAX_SCORE = 100;

// ============================================================
// QUEUE
// ============================================================

const scanQueue = [];

let jobCounter = 0;

function createJobId() {
    jobCounter += 1;
    return `${Date.now()}-${jobCounter}`;
}

function enqueue(targetUrl) {
    return new Promise((resolve, reject) => {
        if (scanQueue.length >= MAX_QUEUE_SIZE) {
            reject(new Error("Scan queue is full"));
            return;
        }

        const job = {
            id: createJobId(),
            targetUrl,
            createdAt: Date.now(),
            resolve,
            reject
        };

        scanQueue.push(job);

        console.log(
            `[QUEUE] Added ${job.id} | ` +
            `waiting=${scanQueue.length}/${MAX_QUEUE_SIZE}`
        );
    });
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================
// SAFE ARRAY PUSH
// ============================================================

function pushLimited(array, item, max) {
    if (array.length < max) {
        array.push(item);
    }
}

// ============================================================
// URL HELPERS
// ============================================================

function getHostname(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return "";
    }
}

function getOrigin(url) {
    try {
        return new URL(url).origin;
    } catch {
        return "";
    }
}

function isValidTargetUrl(url) {
    try {
        const parsed = new URL(url);

        return (
            parsed.protocol === "http:" ||
            parsed.protocol === "https:"
        );
    } catch {
        return false;
    }
}

function isPotentiallyExecutableFilename(filename) {
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

// ============================================================
// BEHAVIORAL SCORING
// ============================================================
//
// These are heuristic indicators, NOT proof that a website is
// malicious.
//
// The host can combine this result with its other modules.
// ============================================================

function analyzeBehavior(telemetry) {
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

    // --------------------------------------------------------
    // Downloads
    // --------------------------------------------------------

    if (telemetry.downloads.length > 0) {
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

        if (executableDownloads.length > 0) {
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

    // --------------------------------------------------------
    // Hidden iframes
    // --------------------------------------------------------

    if (telemetry.dom.hiddenIframeCount > 0) {
        const count = telemetry.dom.hiddenIframeCount;

        const points = Math.min(20, 5 + count * 3);

        addFinding({
            type: "hidden_iframe",
            severity: count >= 3 ? "medium" : "low",
            points,
            details:
                `${count} hidden iframe(s) detected.`,
            evidence: {
                hiddenIframeCount: count,
                iframeCount: telemetry.dom.iframeCount
            }
        });
    }

    // --------------------------------------------------------
    // Excessive iframe usage
    // --------------------------------------------------------

    if (telemetry.dom.iframeCount >= 10) {
        addFinding({
            type: "excessive_iframes",
            severity: "medium",
            points: 8,
            details:
                `${telemetry.dom.iframeCount} iframe(s) detected.`,
            evidence: {
                iframeCount: telemetry.dom.iframeCount
            }
        });
    }

    // --------------------------------------------------------
    // Redirect chain
    // --------------------------------------------------------

    const redirectCount =
        Math.max(
            0,
            telemetry.navigation.redirects.length - 1
        );

    if (redirectCount >= 3) {
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

    // --------------------------------------------------------
    // Popups / new tabs
    // --------------------------------------------------------

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

    // --------------------------------------------------------
    // Excessive external scripts
    // --------------------------------------------------------

    if (telemetry.dom.externalScriptCount >= 20) {
        addFinding({
            type: "excessive_external_scripts",
            severity: "low",
            points: 5,
            details:
                `${telemetry.dom.externalScriptCount} external ` +
                "scripts detected.",
            evidence: {
                externalScriptCount:
                    telemetry.dom.externalScriptCount
            }
        });
    }

    // --------------------------------------------------------
    // Large number of network requests
    // --------------------------------------------------------

    if (telemetry.requests.length >= 200) {
        addFinding({
            type: "high_network_activity",
            severity: "low",
            points: 5,
            details:
                `${telemetry.requests.length} network requests ` +
                "observed during scanning.",
            evidence: {
                requestCount: telemetry.requests.length
            }
        });
    }

    // --------------------------------------------------------
    // Password form
    // --------------------------------------------------------

    if (telemetry.dom.passwordFieldCount > 0) {
        addFinding({
            type: "password_form",
            severity: "low",
            points: 3,
            details:
                "A password input was detected on the page.",
            evidence: {
                passwordFieldCount:
                    telemetry.dom.passwordFieldCount
            }
        });
    }

    // --------------------------------------------------------
    // Dialog abuse
    // --------------------------------------------------------

    if (telemetry.dialogs.length >= 3) {
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

    // --------------------------------------------------------
    // Browser notification requests
    // --------------------------------------------------------

    if (telemetry.permissions.notificationRequests > 0) {
        addFinding({
            type: "notification_permission_request",
            severity: "low",
            points: 4,
            details:
                "The page attempted to request browser " +
                "notification permission.",
            evidence: {
                count:
                    telemetry.permissions.notificationRequests
            }
        });
    }

    // --------------------------------------------------------
    // Suspicious page text
    // --------------------------------------------------------

    if (telemetry.dom.suspiciousText.length > 0) {
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

    // --------------------------------------------------------
    // Final score
    // --------------------------------------------------------

    score = Math.min(MAX_SCORE, score);

    let riskLevel;

    if (score < 20) {
        riskLevel = "low";
    } else if (score < 50) {
        riskLevel = "suspicious";
    } else if (score < 75) {
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
// PLAYWRIGHT SCANNER
// ============================================================

async function scanWithPlaywright(targetUrl, workerId, jobId) {
    const startTime = Date.now();

    let browser = null;
    let context = null;

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

    try {
        console.log(
            `[WORKER ${workerId}] [${jobId}] ` +
            `Launching Chromium for ${targetUrl}`
        );

        browser = await chromium.launch({
            headless: true,
            args: [
                "--disable-dev-shm-usage"
            ]
        });

        context = await browser.newContext({
            acceptDownloads: true
        });

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

            if (frame === page.mainFrame()) {
                telemetry.navigation.redirects.push(url);

                pushLimited(
                    telemetry.navigation.mainFrameNavigations,
                    {
                        url,
                        timestamp: Date.now()
                    },
                    MAX_REDIRECTS
                );
            } else {
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
            try {
                await dialog.dismiss();
            } catch {}
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

        try {
            await page.goto(targetUrl, {
                waitUntil: "domcontentloaded",
                timeout: NAVIGATION_TIMEOUT
            });
        } catch (error) {
            telemetry.errors.push({
                stage: "navigation",
                message: error.message
            });
        }

        // ====================================================
        // BOUNDED OBSERVATION PERIOD
        // ====================================================

        await page.waitForTimeout(OBSERVATION_TIME);

        // ====================================================
        // DOM ANALYSIS
        // ====================================================

        try {
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

                function isHidden(element) {
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

                for (const iframe of iframes) {
                    if (isHidden(iframe)) {
                        hiddenIframeCount++;
                    }
                }

                for (const element of all) {
                    if (isHidden(element)) {
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
        } catch (error) {
            telemetry.errors.push({
                stage: "dom-analysis",
                message: error.message
            });
        }

        // ====================================================
        // NOTIFICATION PERMISSION CHECK
        // ====================================================

        try {
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
        } catch {
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

            telemetry
        };

    } catch (error) {
        return {
            success: false,

            workerId,
            jobId,

            target: targetUrl,

            suspicionScore: 0,

            riskLevel: "unknown",

            findings: [],

            error: error.message,

            telemetry
        };

    } finally {
        // ====================================================
        // ALWAYS CLEAN UP
        // ====================================================

        try {
            if (context) {
                await context.close();
            }
        } catch {}

        try {
            if (browser) {
                await browser.close();
            }
        } catch {}

        console.log(
            `[WORKER ${workerId}] [${jobId}] Chromium closed`
        );
    }
}

// ============================================================
// WORKER
// ============================================================

async function worker(workerId) {
    console.log(`[WORKER ${workerId}] Started`);

    while (true) {
        if (scanQueue.length === 0) {
            await sleep(50);
            continue;
        }

        const job = scanQueue.shift();

        if (!job) {
            continue;
        }

        console.log(
            `[WORKER ${workerId}] ` +
            `Picked ${job.id} | ${job.targetUrl} | ` +
            `remaining=${scanQueue.length}`
        );

        try {
            const result = await scanWithPlaywright(
                job.targetUrl,
                workerId,
                job.id
            );

            job.resolve(result);
        } catch (error) {
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

function startWorkers() {
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

    if (scanQueue.length >= MAX_QUEUE_SIZE) {
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

    try {
        console.log(
            `[API] Queuing scan: ${targetUrl}`
        );

        const result = await enqueue(targetUrl);

        return res.json({
            status: "completed",
            target: targetUrl,
            result
        });

    } catch (error) {
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
            count: WORKER_COUNT
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
    console.log(`Observation      : ${OBSERVATION_TIME} ms`);
    console.log("==============================================");
    console.log("[VM] Server ready");
});

