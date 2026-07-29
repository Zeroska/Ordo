# Workflow: Decide the next pivot

Given the current cluster and open leads, pick the single highest-value next move.

## Steps

1. **List open leads.** From the assessment: unresolved indicators, un-run reverse
   lookups, domains with thin data, named identities not yet reverse-searched.

2. **Score each by expected yield ÷ cost (§5).**
   - yield: will it *confirm or kill* the hypothesis, or just add volume?
   - cost: free/passive (crt.sh, Wayback, KB) < paid credits (FOFA, WhoisXML) < attribution risk.
   - a reverse lookup on a **named identity** usually beats another artifact sweep.

3. **Run the top pivot with the right collector**, then re-ingest:
   ```bash
   # example — reverse-WHOIS on a leaked registrant name via WebPivot's WHOIS tool
   python3 WebPivot/tools/whois_enrich.py --reverse-name "Registrant Name" --search-type historic
   # example — expand a domain and fold results back into the KB
   python3 WebPivot/tools/pivot_extract.py https://newdomain.example --pretty -o cases/x.json
   python3 tools/kb/ingest_webpivot.py --kb knowledge cases/x.json
   ```

4. **Re-correlate.** Re-run `--shared`; if the new domain joins an existing cluster, the
   hypothesis strengthened. If it introduces a conflicting artifact, revise.

5. **Stop condition.** Halt when new pivots stop adding domains for K rounds, or the
   remaining leads are all noise-tier. Record what you deliberately did NOT chase.
