<footer>
  <span class="state"><span class="dot" aria-hidden="true"></span>IDLE</span>
  <span>STAGE --/--</span>
  <span>--:--:--</span>
  <span>-- ev/s</span>
  <span class="counts">
    <span><b class="critical">C</b>--</span>
    <span><b class="high">H</b>--</span>
    <span><b class="medium">M</b>--</span>
    <span><b class="low">L</b>--</span>
    <span><b class="info">I</b>--</span>
  </span>
  <span class="health">engine · tools</span>
</footer>

<style>
  footer {
    display: flex;
    align-items: center;
    gap: var(--s4);
    height: 100%;
    padding: 0 var(--s3);
    overflow: hidden;
    background: var(--bg-0);
    border-top: 1px solid var(--line-1);
    color: var(--tx-mid);
    font: var(--w-body) var(--fs-mono)/var(--lh-micro) var(--font-mono);
    font-variant-numeric: tabular-nums lining-nums;
    white-space: nowrap;
  }
  .state {
    display: inline-flex;
    align-items: center;
    gap: var(--s1);
    color: var(--tx-mid);
    font: var(--w-label) var(--fs-label)/var(--lh-label) var(--font-label);
    letter-spacing: var(--tr-label);
  }
  .dot { width: var(--live-dot); height: var(--live-dot); border: 1px solid var(--tx-off); }
  .counts { display: flex; gap: var(--s3); }
  b { margin-right: var(--s1); font-weight: var(--w-body); }
  .critical { color: var(--sev-critical); }
  .high { color: var(--sev-high); }
  .medium { color: var(--sev-medium); }
  .low { color: var(--sev-low); }
  .info { color: var(--sev-info); }
  .health { margin-left: auto; color: var(--tx-lo); }
</style>
