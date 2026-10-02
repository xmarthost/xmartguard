import { describe, expect, it } from 'vitest';
import { eachLimit, single } from '../src/agents/limit.js';

describe('eachLimit', () => {
  it('keeps order, caps concurrency, and a slow item holds up only its worker', async () => {
    let running = 0;
    let peak = 0;
    const started: number[] = [];
    const out = await eachLimit([200, 10, 10, 10, 10, 10], 2, async (ms, i) => {
      running++;
      peak = Math.max(peak, running);
      started.push(i);
      await new Promise((r) => setTimeout(r, ms));
      running--;
      return i * 2;
    });
    expect(out).toEqual([0, 2, 4, 6, 8, 10]);
    expect(peak).toBe(2);
    // Items 1..5 all ran on the second worker while item 0 was still busy.
    expect(started.slice(0, 6)).toEqual([0, 1, 2, 3, 4, 5]);
  });
});

describe('single', () => {
  it('skips a run while the previous one is still going', async () => {
    let n = 0;
    const job = single(async () => {
      n++;
      await new Promise((r) => setTimeout(r, 50));
    });
    await Promise.all([job(), job(), job()]);
    expect(n).toBe(1);
    await job();
    expect(n).toBe(2);
  });
});
