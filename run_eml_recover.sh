#!/bin/bash
# run_eml_recover.sh - cron runs it every 4 hours: 0005 0405 0805 1205 1605 2005
#
# Input : $INPUT_ROOT/DD-MM-YYYY/HHMM/*.eml   (each HHMM folder fills in ~2 minutes)
# Output: $OUTPUT_BASE/DD-MM-YYYY/             (Extracted/, Not Extracted/, recovery_report.csv)
#
# Every HHMM folder of today (and of yesterday on the 0005 run) is checked:
#   modified in the last 2 minutes ............. SKIP, still being dumped
#   HHMM after the last scan ................... RUN, new folder for this run
#   HHMM up to the last scan, but modified at
#   or after (last scan - 2 minutes) ........... RUN, the last scan skipped it
#   anything else .............................. already done by an earlier run
#
# "Modified" is the HHMM folder's own mtime, which changes each time a file is
# dumped into it. Once the next HHMM folder starts, the previous one never changes.
#
# Crontab:
#   5 0,4,8,12,16,20 * * * /opt/eml/run_eml_recover.sh >> /var/log/eml_recover.log 2>&1
# Test a given slot:
#   RUN_TIME="2026-10-19 08:05" /opt/eml/run_eml_recover.sh

INPUT_ROOT="${INPUT_ROOT:-/data/Input}"
OUTPUT_BASE="${OUTPUT_BASE:-/data/Output}"
SCRIPT="${SCRIPT:-$(dirname "$(readlink -f "$0")")/eml_recover.py}"
PYTHON="/usr/bin/python3"
PY_OPTS=(--min-size 1024)            # extra eml_recover.py options
INTERVAL_MIN=240                     # minutes between cron runs
DANGER_MIN=2                         # minutes an HHMM folder takes to fill

RUN_TIME="${RUN_TIME:-$(date '+%Y-%m-%d %H:%M')}"

TODAY=$(date -d "$RUN_TIME" +%d-%m-%Y)                  # 12-10-2026
INPUT_BASE="$INPUT_ROOT/$TODAY"                          # today's input folder

if [ ! -d "$OUTPUT_BASE/$TODAY" ]; then                  # today's output folder
    mkdir -p "$OUTPUT_BASE/$TODAY"
fi

NOW=$(date -d "$RUN_TIME" +%s)                           # this scan, e.g. 08:05
NOW_HHMM=$(date -d "@$NOW" +%H%M)
LAST=$(( NOW - INTERVAL_MIN * 60 ))                      # last scan, e.g. 04:05
LAST_HHMM=$(date -d "@$LAST" +%H%M)
DANGER=$(( DANGER_MIN * 60 ))

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }

scan_day() {                                             # scan_day <input folder of one day>
    local day_dir=$1 day folder hhmm folder_time modified reason
    day=$(basename "$day_dir")                           # DD-MM-YYYY
    [ -d "$day_dir" ] || return
    mkdir -p "$OUTPUT_BASE/$day"

    for folder in "$day_dir"/*/; do
        folder=${folder%/}
        hhmm=$(basename "$folder")
        [[ $hhmm =~ ^([01][0-9]|2[0-3])[0-5][0-9]$ ]] || continue

        folder_time=$(date -d "${day:6:4}-${day:3:2}-${day:0:2} ${hhmm:0:2}:${hhmm:2:2}" +%s)
        modified=$(stat -c %Y "$folder")                 # folder's last modification (epoch)

        if (( folder_time > NOW )); then
            continue                                     # not due yet
        elif (( modified >= NOW - DANGER )); then
            log "SKIP $day/$hhmm: still being dumped (modified $(date -d "@$modified" +%H:%M:%S))"
            continue
        elif (( folder_time > LAST )); then
            reason="new since last scan $LAST_HHMM"
        elif (( modified >= LAST - DANGER )); then
            reason="skipped by last scan $LAST_HHMM"
        else
            continue                                     # done by an earlier run
        fi

        log "RUN  $day/$hhmm: $reason"
        "$PYTHON" "$SCRIPT" --input "$folder" --output "$OUTPUT_BASE/$day" "${PY_OPTS[@]}" \
            || log "FAIL $day/$hhmm: eml_recover.py exited $?"
    done
}

log "scan $TODAY $NOW_HHMM, last scan $LAST_HHMM"
if [ "$(date -d "@$LAST" +%d-%m-%Y)" != "$TODAY" ]; then    # 0005 run: finish yesterday
    scan_day "$INPUT_ROOT/$(date -d "@$LAST" +%d-%m-%Y)"
fi
scan_day "$INPUT_BASE"
log "scan done"
