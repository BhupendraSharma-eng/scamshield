/** Prepare two audio chunks concurrently, but commit every result in capture order. */
export class OrderedAudioQueue<Input, Prepared> {
  private jobs: { input: Input; ready: boolean; started?: boolean; value?: Prepared; error?: unknown; failed?: boolean }[] = [];
  private preparing = 0;
  private committing = false;
  private waiters: (() => void)[] = [];

  constructor(
    private prepare: (input: Input) => Promise<Prepared>,
    private commit: (input: Input, prepared: Prepared) => Promise<void>,
    private onError: (error: unknown) => void,
    private concurrency = 2,
  ) {}

  push(input: Input) {
    this.jobs.push({ input, ready: false });
    this.pump();
  }

  drain(): Promise<void> {
    if (!this.jobs.length && !this.preparing && !this.committing) return Promise.resolve();
    return new Promise(resolve => this.waiters.push(resolve));
  }

  private pump() {
    for (const job of this.jobs) {
      if (this.preparing >= this.concurrency) break;
      // A preparing job has a separate marker so it is never launched twice.
      if (job.ready || job.started) continue;
      job.started = true;
      this.preparing++;
      void (async () => this.prepare(job.input))().then(value => { job.value = value; }, error => {
        job.error = error; job.failed = true;
      }).finally(() => {
        job.ready = true;
        this.preparing--;
        this.pump();
        void this.commitReady();
      });
    }
  }

  private async commitReady() {
    if (this.committing) return;
    this.committing = true;
    try {
      while (this.jobs[0]?.ready) {
        const job = this.jobs.shift()!;
        try {
          if (job.failed) throw job.error;
          await this.commit(job.input, job.value as Prepared);
        } catch (error) { this.onError(error); }
      }
    } finally {
      this.committing = false;
      if (!this.jobs.length && !this.preparing) this.waiters.splice(0).forEach(resolve => resolve());
    }
  }
}
