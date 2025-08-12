#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: gadget_top.sh [-n TOP] [-s key] [-o order] <logfile>

Sort keys (by numeric columns; defaults to cache_entries total):
  cache_entries | total_cache | duration_ns | gates
Extras:
  count | sum_cache_entries | sum_total_cache | sum_duration_ns | sum_gates
  avg_cache_entries | avg_total_cache | avg_duration_ns | avg_gates
  max_cache_entries | max_total_cache | max_gates | last_gates

Notes:
- Table also shows human-readable durations (sum_duration / avg_duration), but sorting uses raw *_ns.
EOF
}

TOP=0
SORT_KEY="cache_entries"
ORDER="desc"

while getopts ":n:s:o:h" opt; do
  case "$opt" in
    n) TOP="$OPTARG" ;;
    s) SORT_KEY="$OPTARG" ;;
    o) ORDER="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) usage; exit 1 ;;
  esac
done
shift $((OPTIND-1))

LOGFILE="${1:-}"
[ -z "$LOGFILE" ] && { usage; exit 1; }
[ -r "$LOGFILE" ] || { echo "error: cannot read $LOGFILE" >&2; exit 1; }

# Column mapping (1-based; see header printed by awk)
case "$SORT_KEY" in
  cache_entries|sum_cache_entries) COL=3 ;;
  total_cache|sum_total_cache)     COL=4 ;;
  duration_ns|sum_duration_ns)     COL=5 ;;
  gates|sum_gates)                 COL=6 ;;
  count)               COL=2  ;;
  avg_cache_entries)   COL=7  ;;
  avg_total_cache)     COL=8  ;;
  avg_duration_ns)     COL=9  ;;
  avg_gates)           COL=10 ;;
  max_cache_entries)   COL=11 ;;
  max_total_cache)     COL=12 ;;
  max_gates)           COL=13 ;;
  last_gates)          COL=14 ;;
  *) echo "error: invalid -s '$SORT_KEY'"; exit 1 ;;
esac
SORT_FLAG="nr"; [ "$ORDER" = "asc" ] && SORT_FLAG="n"

do_agg() {
  rg -N --no-filename --no-line-number -F 'component_metrics name=' "$LOGFILE" \
  | awk '
    BEGIN { OFS = "\t" }
    function rtrim0(s){ sub(/\.?0+$/,"",s); return s }
    # ns -> best unit (ns, us, ms, s, m, h); ASCII units for safe terminal alignment
    function pretty_ns(x,
                       y, out) {
      if (x < 1000) return x " ns";
      y = x / 1000.0;                 if (y < 1000) return rtrim0(sprintf("%.3f", y)) " us";
      y = y / 1000.0;                 if (y < 1000) return rtrim0(sprintf("%.3f", y)) " ms";
      y = y / 1000.0;                 if (y < 60)   return rtrim0(sprintf("%.3f", y)) " s";
      y = y / 60.0;                   if (y < 60)   return rtrim0(sprintf("%.3f", y)) " m";
      y = y / 60.0;                                  return rtrim0(sprintf("%.3f", y)) " h";
    }
    {
      if (match($0, /name=([^ ]+).*gates=([0-9]+).*cache_entries=([0-9]+).*total_cache=([0-9]+).*duration_ns=([0-9]+)/, m)) {
        name=m[1]; g=m[2]+0; ce=m[3]+0; tc=m[4]+0; dur=m[5]+0
        cnt[name]++
        sum_g[name]+=g
        sum_ce[name]+=ce
        sum_tc[name]+=tc
        sum_dur[name]+=dur
        if (ce>max_ce[name]) max_ce[name]=ce
        if (tc>max_tc[name]) max_tc[name]=tc
        if (g>max_g[name])   max_g[name]=g
        last_g[name]=g
      }
    }
    END {
      printf "gadget\tcount\tsum_cache_entries\tsum_total_cache\tsum_duration_ns\tsum_gates\tavg_cache_entries\tavg_total_cache\tavg_duration_ns\tavg_gates\tmax_cache_entries\tmax_total_cache\tmax_gates\tlast_gates\tsum_duration\tavg_duration\n"
      for (name in cnt) {
        c   = cnt[name]
        sg  = 0 + sum_g[name]
        sce = 0 + sum_ce[name]
        stc = 0 + sum_tc[name]
        sdn = 0 + sum_dur[name]
        ag  = (c ? sg  /c : 0)
        ace = (c ? sce /c : 0)
        atc = (c ? stc /c : 0)
        adn = (c ? sdn /c : 0)
        mg  = 0 + max_g[name]
        mce = 0 + max_ce[name]
        mtc = 0 + max_tc[name]
        lg  = 0 + last_g[name]
        printf "%s\t%d\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\t%.3f\t%d\t%d\t%d\t%d\t%s\t%s\n",
               name, c, sce, stc, sdn, sg, ace, atc, adn, ag, mce, mtc, mg, lg,
               pretty_ns(sdn), pretty_ns(adn)
      }
    }'
}

if [ "$TOP" -gt 0 ]; then
  do_agg | LC_ALL=C sort -t $'\t' -k${COL},${COL}${SORT_FLAG} | head -n $((TOP + 1)) | column -t -s $'\t'
else
  do_agg | LC_ALL=C sort -t $'\t' -k${COL},${COL}${SORT_FLAG} | column -t -s $'\t'
fi
