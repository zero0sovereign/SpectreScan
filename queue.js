const crypto = require('crypto');

class ScanQueue 
{
    constructor({
        quick = null,               // async (job, emit) => null | finalResult
        handler,                    // async (job, emit) => finalResult
        concurrency = 3,            // parallel sandbox scans (= VM WORKERS)
        maxQueue = 300,
        maxWaitMs = 45_000,
        maxTracked = 20_000,
        cacheTtlMs = 5 * 60_000,
        jobTtlMs = 10 * 60_000
    }) 
    
    {
        this.quick = quick;
        this.handler = handler;
        this.concurrency = concurrency;
        this.maxQueue = maxQueue;
        this.maxWaitMs = maxWaitMs;
        this.maxTracked = maxTracked;
        this.cacheTtlMs = cacheTtlMs;
        this.jobTtlMs = jobTtlMs;

        this.pending = [];   // array + head index = O(1) dequeue
        this.head = 0;
        this.active = 0;

        this.jobs = new Map();   // jobId -> job (insertion ordered)
        this.byUrl = new Map();  // url   -> newest job for that url

        this.stats = { submitted: 0, deduped: 0, rejected: 0, completed: 0, failed: 0, expired: 0 };

        setInterval(() => this.sweep(), 5_000).unref();
    }

    get waiting() 
    {
        return this.pending.length - this.head;
    }

    // Returns { job, deduped } or null when the server is too busy.
    submit(url) 
    {
        const now = Date.now();
        const existing = this.byUrl.get(url);

        // Same URL already scanning, or finished recently -> reuse it.
        if 
        (
            existing &&
            existing.status !== 'error' &&
            (!existing.finishedAt || now - existing.finishedAt < this.cacheTtlMs)
        ) 
        
        {
            this.stats.deduped++;
            return { job: existing, deduped: true };
        }

        if (this.waiting >= this.maxQueue || (this.jobs.size >= this.maxTracked && !this._evict())) 
        {
            this.stats.rejected++;
            return null;
        }

        const job = 
        {
            id: crypto.randomUUID(),
            url,
            status: 'preparing',
            createdAt: now,
            seq: 0,
            events: [],
            listeners: new Set(),
            partial: {}          // scratch space shared by quick() and handler()
        };

        this.jobs.set(job.id, job);
        this.byUrl.set(url, job);
        this.stats.submitted++;

        this._begin(job);
        return { job, deduped: false };
    }

    get(id) 
    {
        return this.jobs.get(id) || null;
    }

    // ---- events -----------------------------------------------------------

    emit(job, type, data) 
    {
        const ev = { seq: ++job.seq, type, data };
        job.events.push(ev);

        for (const fn of job.listeners) 
        {
            try { fn(ev); } catch { /* a dead client must never break the scan */ }
        }
    }

    // Replays events after `fromSeq`, then streams new ones.
    // Returns an unsubscribe function, or null if the job is already over.
    subscribe(job, fromSeq, fn) 
    {
        for (const ev of job.events) 
        {
            if (ev.seq > fromSeq) fn(ev);
        }

        if (job.status === 'done' || job.status === 'error') return null;

        job.listeners.add(fn);
        return () => job.listeners.delete(fn);
    }

    // ---- life cycle ---------------------------------------------------------

    async _begin(job) 
    {
        const emit = (t, d) => this.emit(job, t, d);

        try 
        {
            if (this.quick) 
            {
                const early = await this.quick(job, emit);
                if (early) return this._finish(job, early);   // no sandbox needed
            }
        } 
        
        catch (err) 
        {
            return this._fail(job, err);
        }

        job.status = 'queued';
        job.enqueuedAt = Date.now();
        this.pending.push(job);
        this._drain();

        if (job.status === 'queued') 
        {
            emit('queued', { position: this.waiting });
        }
    }

    _drain() 
    {
        while (this.active < this.concurrency && this.head < this.pending.length) 
        {
            const job = this.pending[this.head];
            this.pending[this.head++] = undefined;   // let the GC have it

            // compact occasionally so the array doesn't grow forever
            if (this.head > 1024 && this.head * 2 > this.pending.length) 
            {
                this.pending = this.pending.slice(this.head);
                this.head = 0;
            }

            if (Date.now() - job.enqueuedAt > this.maxWaitMs) 
            {
                this.stats.expired++;
                this._fail(job, new Error('Server is busy: your scan waited too long in the queue.'));
                continue;
            }

            this._run(job);
        }
    }

    async _run(job) 
    {
        this.active++;
        job.status = 'running';
        job.startedAt = Date.now();
        this.emit(job, 'started', { queueMs: job.startedAt - job.enqueuedAt });

        try 
        {
            const result = await this.handler(job, (t, d) => this.emit(job, t, d));
            this._finish(job, result);
        } 
        
        catch (err) 
        {
            this._fail(job, err);
        } 
        
        finally 
        {
            this.active--;
            this._drain();
        }
    }

    _finish(job, result) 
    {
        job.result = result;
        job.status = 'done';
        job.finishedAt = Date.now();
        this.stats.completed++;

        this.emit(job, 'done', 
        {
            verdict: result.verdict,
            totalMs: job.finishedAt - job.createdAt,
            queueMs: job.startedAt ? job.startedAt - job.enqueuedAt : 0,
            scanMs: job.startedAt ? job.finishedAt - job.startedAt : 0
        });
    }

    _fail(job, err) 
    {
        job.error = err && err.message ? err.message : String(err);
        job.status = 'error';
        job.finishedAt = Date.now();
        this.stats.failed++;

        this.emit(job, 'error', { message: job.error });
    }

    // ---- housekeeping -------------------------------------------------------

    // Fail jobs that have waited longer than maxWaitMs (they're oldest-first).
    _expireWaiting() 
    {
        const now = Date.now();

        while (this.head < this.pending.length) 
        {
            const job = this.pending[this.head];
            if (!job || now - job.enqueuedAt <= this.maxWaitMs) break;

            this.pending[this.head++] = undefined;
            this.stats.expired++;
            this._fail(job, new Error('Server is busy: your scan waited too long in the queue.'));
        }
    }

    // Drop the oldest finished jobs to get under the cap. Returns true if space was freed.
    _evict() 
    {
        const target = Math.floor(this.maxTracked * 0.9);

        for (const [id, job] of this.jobs) 
        {
            if (this.jobs.size <= target) break;
            if (!job.finishedAt) continue;   // never evict running/queued jobs

            this.jobs.delete(id);
            if (this.byUrl.get(job.url) === job) this.byUrl.delete(job.url);
        }

        return this.jobs.size < this.maxTracked;
    }

    // aggressive = called under memory pressure: forget finished jobs sooner.
    sweep(aggressive = false) 
    {
        this._expireWaiting();

        const ttl = aggressive ? 30_000 : this.jobTtlMs;
        const now = Date.now();

        for (const [id, job] of this.jobs) 
        {
            if (job.finishedAt && now - job.finishedAt > ttl) 
            {
                this.jobs.delete(id);
                if (this.byUrl.get(job.url) === job) this.byUrl.delete(job.url);
            }
        }
    }

    snapshot() 
    {
        return {
            waiting: this.waiting,
            active: this.active,
            concurrency: this.concurrency,
            maxQueue: this.maxQueue,
            tracked: this.jobs.size,
            ...this.stats
        };
    }
}

module.exports = ScanQueue;
