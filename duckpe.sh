#!/usr/bin/env bash
# =============================================================================
#  Linux Yerel Yetki Yükseltme Kontrolcüsü (Local Privilege Escalation Checker)
# -----------------------------------------------------------------------------
#  Kullanım : ./lpe-check.sh [seçenekler]
# =============================================================================

set -o pipefail

export LC_ALL=C

VERSION="2.0"
TOTAL_STEPS=18
CRIT=0
HIGH=0
WARN=0
FOUND=0
VERBOSE=0
JSON_MODE=0
OFFLINE=0
NO_PASSWORD=0
SELFTEST=0
FAIL_ON="warn"
ONLY_STEPS=""
CMD_TIMEOUT=10
CURRENT_STEP=0
TMPDIR_RUN=""

declare -a F_STEP=() F_SEV=() F_MSG=()
declare -a N_STEP=() N_KIND=() N_MSG=()
declare -A seen_ports=()

usage() {
    cat <<'EOF'
Kullanım: lpe-check.sh [seçenekler]

  -v, --verbose          Tüm SUID/SGID dosyalarını ve ayrıntıları göster
      --json             Makine okunabilir JSON çıktısı üret
      --offline          İnternet/Exploit-DB sorgusunu kapat
      --no-password      sudo -l için parola sorma
      --fail-on=SEV      Çıkış eşiği: warn (varsayılan), high, crit, none
      --only=STEPS       Yalnızca verilen adımları çalıştır (örn. 1,11,15)
      --timeout=SN       Dış komut zaman aşımı (saniye, varsayılan 10)
      --selftest         Yerleşik birim testlerini çalıştır
  -h, --help             Bu yardımı göster

Çıkış kodları: 0 temiz, 1 uyarı, 2 yüksek, 3 kritik.
EOF
}

arg_error() {
    printf 'Hata: %s\n' "$*" >&2
    printf 'Yardım için --help kullanın.\n' >&2
    exit 2
}

while (($#)); do
    case "$1" in
        -v|--verbose) VERBOSE=1 ;;
        -h|--help) usage; exit 0 ;;
        --json) JSON_MODE=1 ;;
        --offline) OFFLINE=1 ;;
        --no-password) NO_PASSWORD=1 ;;
        --selftest) SELFTEST=1 ;;
        --fail-on)
            [[ $# -ge 2 ]] || arg_error "--fail-on için değer gerekli"
            FAIL_ON="$2"; shift ;;
        --fail-on=*) FAIL_ON="${1#*=}" ;;
        --only)
            [[ $# -ge 2 ]] || arg_error "--only için adım listesi gerekli"
            ONLY_STEPS="${ONLY_STEPS:+$ONLY_STEPS,}$2"; shift ;;
        --only=*) ONLY_STEPS="${ONLY_STEPS:+$ONLY_STEPS,}${1#*=}" ;;
        --timeout)
            [[ $# -ge 2 ]] || arg_error "--timeout için saniye gerekli"
            CMD_TIMEOUT="$2"; shift ;;
        --timeout=*) CMD_TIMEOUT="${1#*=}" ;;
        --) shift; break ;;
        *) arg_error "Bilinmeyen argüman: $1" ;;
    esac
    shift
done

case "$FAIL_ON" in
    warn|high|crit|none) ;;
    *) arg_error "--fail-on değeri warn|high|crit|none olmalı" ;;
esac
if [[ -n "$ONLY_STEPS" && ! "$ONLY_STEPS" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
    arg_error "--only virgülle ayrılmış adım numaraları olmalı (örn. 1,11,15)"
fi
if [[ -n "$ONLY_STEPS" ]]; then
    for only_n in ${ONLY_STEPS//,/ }; do
        only_n=$((10#$only_n))
        if ((only_n < 1 || only_n > TOTAL_STEPS)); then
            arg_error "--only adımı aralık dışında: $only_n (1-$TOTAL_STEPS)"
        fi
    done
fi
if [[ "$CMD_TIMEOUT" =~ ^[0-9]+$ ]]; then
    CMD_TIMEOUT=$((10#$CMD_TIMEOUT))
fi
if ! [[ "$CMD_TIMEOUT" =~ ^[0-9]+$ ]] || ((CMD_TIMEOUT < 1)); then
    arg_error "--timeout 1 veya daha büyük bir tam sayı olmalı"
fi

# ---------------------------------------------------------------------------
# Renkler
# ---------------------------------------------------------------------------
if ((JSON_MODE)) || [[ ! -t 1 || -n "${NO_COLOR:-}" ]]; then
    RESET='' BOLD='' DIM='' RED='' GREEN='' YELLOW=''
    BLUE='' MAGENTA='' CYAN='' ON_RED=''
else
    RESET=$'\033[0m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RED=$'\033[1;31m'
    GREEN=$'\033[1;32m'
    YELLOW=$'\033[1;33m'
    BLUE=$'\033[1;34m'
    MAGENTA=$'\033[1;35m'
    CYAN=$'\033[1;36m'
    ON_RED=$'\033[1;97;41m'
fi

# ---------------------------------------------------------------------------
# Çıktı yardımcıları
# ---------------------------------------------------------------------------
CURRENT_STEP=0

step() {
    CURRENT_STEP="$1"
    ((JSON_MODE)) && return 0
    printf '\n%s[ADIM %02d/%d]%s %s%s%s\n' \
        "$BLUE" "$1" "$TOTAL_STEPS" "$RESET" "$CYAN$BOLD" "$2" "$RESET"
}

add_finding() {
    F_STEP+=("$CURRENT_STEP")
    F_SEV+=("$1")
    F_MSG+=("$2")
}

note_add() {
    N_STEP+=("$CURRENT_STEP")
    N_KIND+=("$1")
    N_MSG+=("$2")
}

crit() {
    ((CRIT++))
    add_finding critical "$*"
    ((JSON_MODE)) || printf '  %s[KRİTİK]%s %s\n' "$ON_RED" "$RESET" "$*"
}

high() {
    ((HIGH++))
    add_finding high "$*"
    ((JSON_MODE)) || printf '  %s[YÜKSEK]%s %s\n' "$RED" "$RESET" "$*"
}

warn() {
    ((WARN++))
    add_finding warning "$*"
    ((JSON_MODE)) || printf '  %s[UYARI]%s %s\n' "$YELLOW" "$RESET" "$*"
}

ok() {
    note_add ok "$*"
    ((JSON_MODE)) || printf '  %s[OK]%s %s\n' "$GREEN" "$RESET" "$*"
}

info() {
    note_add info "$*"
    ((JSON_MODE)) || printf '  %s[BİLGİ]%s %s\n' "$DIM" "$RESET" "$*"
}

found() {
    ((FOUND++))
    add_finding finding "$*"
    ((JSON_MODE)) || printf '  %s[BULGU]%s %s\n' "$MAGENTA" "$RESET" "$*"
}

detail() {
    note_add detail "$*"
    ((JSON_MODE)) || printf '         %s%s%s\n' "$DIM" "$*" "$RESET"
}

have() { command -v "$1" >/dev/null 2>&1; }

should_run() {
    [[ -z "$ONLY_STEPS" ]] && return 0
    [[ ",$ONLY_STEPS," == *",$1,"* ]]
}

# Root oturumunda izin tabanlı kontroller yanıltıcıdır.
PERM_CHECKS=1
if ((EUID == 0)); then
    PERM_CHECKS=0
fi

# ---------------------------------------------------------------------------
# JSON, çıkış kodu, bağımlılık ve temizlik
# ---------------------------------------------------------------------------
json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    s=${s//$'\b'/\\b}
    s=${s//$'\f'/\\f}
    printf '%s' "$s"
}

compute_exit() {
    case "$FAIL_ON" in
        none) printf '0' ;;
        crit)
            if ((CRIT > 0)); then printf '3'; else printf '0'; fi ;;
        high)
            if ((CRIT > 0)); then printf '3'
            elif ((HIGH > 0)); then printf '2'
            else printf '0'; fi ;;
        warn|*)
            if ((CRIT > 0)); then printf '3'
            elif ((HIGH > 0)); then printf '2'
            elif ((WARN > 0)); then printf '1'
            else printf '0'; fi ;;
    esac
}

print_json_error() {
    printf '{"version":"%s","error":"%s"}\n' \
        "$(json_escape "$VERSION")" "$(json_escape "$1")"
}

print_json() {
    local i sep rc ts host usr kern
    rc=$(compute_exit)
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
    host=$(hostname 2>/dev/null || true)
    usr=$(id -un 2>/dev/null || true)
    kern=$(uname -r 2>/dev/null || true)

    printf '{"version":"%s","meta":{"timestamp":"%s","hostname":"%s","user":"%s","kernel":"%s"},"summary":{"critical":%d,"high":%d,"warning":%d,"finding":%d},"exit_code":%d,"findings":[' \
        "$(json_escape "$VERSION")" "$(json_escape "$ts")" "$(json_escape "$host")" \
        "$(json_escape "$usr")" "$(json_escape "$kern")" \
        "$CRIT" "$HIGH" "$WARN" "$FOUND" "$rc"

    sep=""
    for i in "${!F_MSG[@]}"; do
        printf '%s{"step":%s,"severity":"%s","message":"%s"}' \
            "$sep" "${F_STEP[$i]}" "$(json_escape "${F_SEV[$i]}")" \
            "$(json_escape "${F_MSG[$i]}")"
        sep=","
    done

    printf '],"notes":['
    sep=""
    for i in "${!N_MSG[@]}"; do
        printf '%s{"step":%s,"kind":"%s","message":"%s"}' \
            "$sep" "${N_STEP[$i]}" "$(json_escape "${N_KIND[$i]}")" \
            "$(json_escape "${N_MSG[$i]}")"
        sep=","
    done
    printf ']}\n'
}

OPTIONAL_MISSING=()
check_dependencies() {
    local c missing=()
    for c in bash find sort timeout awk sed grep stat mktemp; do
        have "$c" || missing+=("$c")
    done
    if ((${#missing[@]} > 0)); then
        if ((JSON_MODE)); then
            print_json_error "Gerekli komut(lar) bulunamadı: ${missing[*]}"
        else
            printf '  [HATA] Gerekli komut(lar) bulunamadı: %s\n' "${missing[*]}" >&2
            printf 'Gerekli bağımlılıklar eksik; tarama başlatılmadı.\n' >&2
        fi
        exit 2
    fi

    for c in getcap ss netstat systemctl findmnt curl searchsploit python3 jq sudo; do
        have "$c" || OPTIONAL_MISSING+=("$c")
    done
}

setup_tmpdir() {
    if TMPDIR_RUN=$(mktemp -d "${TMPDIR:-/tmp}/lpe-check.XXXXXX" 2>/dev/null); then
        return 0
    fi
    TMPDIR_RUN="${TMPDIR:-/tmp}/lpe-check.$$"
    mkdir -p "$TMPDIR_RUN" 2>/dev/null || TMPDIR_RUN=""
}

cleanup_tmpdir() {
    if [[ -n "$TMPDIR_RUN" && -d "$TMPDIR_RUN" ]]; then
        rm -rf -- "$TMPDIR_RUN"
    fi
}
trap cleanup_tmpdir EXIT
trap 'cleanup_tmpdir; exit 130' INT TERM

# ---------------------------------------------------------------------------
# Ortak dosya/mount/kullanıcı yardımcıları
# ---------------------------------------------------------------------------
is_sticky_dir() {
    local d="$1" mode
    [[ -d "$d" ]] || return 1
    mode=$(stat -c '%a' -- "$d" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1
    (( (8#$mode & 01000) != 0 ))
}

mount_options() {
    local path="$1"
    if have findmnt; then
        findmnt -T "$path" -no OPTIONS 2>/dev/null | head -n1
    else
        awk -v p="$path" '
            BEGIN { best = ""; opts = "" }
            {
                mp = $2
                gsub(/\\040/, " ", mp)
                if (index(p, mp) == 1 && length(mp) > length(best)) {
                    best = mp; opts = $4
                }
            }
            END { print opts }
        ' /proc/self/mounts 2>/dev/null
    fi
}

mount_has_opt() {
    local path="$1" opt="$2"
    mount_options "$path" | tr ',' '\n' | grep -Fxq "$opt"
}

is_standard_suid_path() {
    local path="$1"
    case "$path" in
        /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/libexec/*|/lib/*|/lib64/*|/snap/*|/opt/*)
            is_standard_suid "$(basename -- "$path")" ;;
        *) return 1 ;;
    esac
}

# Cron komutunun hedef dosyayı gerçekten çalıştırıp çalıştırmadığını kabaca belirler.
cron_target_is_executed() {
    local cmd="$1" target="$2" segment

    # Kabuk denetim operatörleriyle ayrılmış her komut parçasını ayrı değerlendir.
    # Örn. "test -x /tmp/x && /tmp/x" ifadesinde ikinci parça hedefi çalıştırır.
    while IFS= read -r segment || [[ -n "$segment" ]]; do
        [[ -z "${segment//[[:space:]]/}" ]] && continue
        cron_segment_executes "$segment" "$target" && return 0
    done < <(printf '%s' "$cmd" | sed 's/&&/\n/g; s/||/\n/g; s/;/\n/g; s/|/\n/g')
    return 1
}

cron_segment_executes() {
    local cmd="$1" target="$2"
    local -a words=()
    local i=0 n w base

    read -r -a words <<< "$cmd"
    n=${#words[@]}
    ((n == 0)) && return 1

    while ((i < n)); do
        w="${words[$i]}"
        base=$(basename -- "$w" 2>/dev/null || printf '%s' "$w")
        case "$base" in
            env)
                ((i++))
                while ((i < n)); do
                    w="${words[$i]}"
                    if [[ "$w" == -* || "$w" == *=* ]]; then ((i++)); continue; fi
                    break
                done
                ;;
            timeout)
                ((i++))
                while ((i < n)); do
                    w="${words[$i]}"
                    if [[ "$w" == -* || "$w" =~ ^[0-9]+(\.[0-9]+)?[smhd]?$ ]]; then
                        ((i++)); continue
                    fi
                    break
                done
                ;;
            flock)
                ((i++))
                while ((i < n)); do
                    w="${words[$i]}"
                    if [[ "$w" == -* ]]; then ((i++)); continue; fi
                    ((i++))   # kilit dosyası
                    break
                done
                ;;
            nice|ionice|nohup|setsid|stdbuf|xargs|exec|command|builtin|then|do|else)
                ((i++))
                while ((i < n)); do
                    w="${words[$i]}"
                    if [[ "$w" == -* || "$w" =~ ^[0-9]+$ ]]; then ((i++)); continue; fi
                    break
                done
                ;;
            sudo|doas|runuser)
                ((i++))
                while ((i < n)); do
                    w="${words[$i]}"
                    case "$w" in
                        -u|-g|-p|-r|-t|-C) ((i += 2)); continue ;;
                        -*) ((i++)); continue ;;
                    esac
                    break
                done
                ;;
            *)
                break
                ;;
        esac
    done

    ((i < n)) || return 1
    w="${words[$i]}"
    base=$(basename -- "$w" 2>/dev/null || printf '%s' "$w")
    case "$base" in
        bash|sh|dash|zsh|ksh|python|python2|python3|perl|ruby|php|node|source|.)
            return 0 ;;
        run-parts)
            [[ -d "$target" ]] && return 0 ;;
    esac
    [[ "$w" == "$target" ]] && return 0
    return 1
}

# PATH benzeri ':' ile ayrılmış değerleri denetler.
check_path_value() {
    local label="$1" value="$2" d
    local -a dirs=()
    [[ -z "$value" ]] && return 0
    if [[ "$value" == *::* || "$value" == :* || "$value" == *: ]]; then
        high "[kesin] $label boş bir dizin bileşeni içeriyor: $value"
    fi
    IFS=: read -r -a dirs <<< "$value"
    for d in "${dirs[@]}"; do
        if [[ -z "$d" ]]; then
            continue
        fi
        if [[ "$d" == "." ]]; then
            high "[kesin] $label içinde '.' var: $value"
            continue
        fi
        if [[ "$d" != /* ]]; then
            warn "[kesin] $label göreli dizin içeriyor: $d"
        fi
        if [[ -e "$d" && ! -d "$d" ]]; then
            warn "$label: dizin değil: $d"
            continue
        fi
        if [[ -d "$d" && -w "$d" ]]; then
            local downer dmode
            downer=$(stat -c '%U' -- "$d" 2>/dev/null)
            dmode=$(stat -c '%a' -- "$d" 2>/dev/null)
            if is_sticky_dir "$d"; then
                warn "[kesin] $label yazılabilir dizin (sticky): $d"
            elif [[ -n "$dmode" && "$dmode" =~ ^[0-7]+$ ]] && (( (8#$dmode & 0002) != 0 )); then
                high "[kesin] $label dünya tarafından yazılabilir: $d"
            elif [[ "$downer" == "$(id -un 2>/dev/null)" ]]; then
                info "$label kullanıcıya ait yazılabilir dizin (tek başına yükseltme değil): $d"
            else
                warn "[aday] $label yazılabilir dizin: $d (sahip: ${downer:-?})"
            fi
        fi
    done
}

check_env_path_var() {
    local var="$1" val="${!1:-}" f
    local -a files=()
    [[ -z "$val" ]] && return 0
    info "$var=$val"
    if [[ "$var" == "LD_PRELOAD" ]]; then
        IFS=': ' read -r -a files <<< "$val"
        for f in "${files[@]}"; do
            [[ -z "$f" ]] && continue
            if [[ -w "$f" ]]; then
                high "[kesin] $var yazılabilir dosyaya işaret ediyor: $f"
            elif [[ ! -e "$f" ]]; then
                warn "$var: dosya yok: $f"
            fi
        done
    else
        check_path_value "$var" "$val"
    fi
}

check_nfs_exports_file() {
    local f="$1" line found=0
    [[ -r "$f" ]] || return 1
    while IFS= read -r line; do
        line=${line%%#*}
        [[ -z "${line//[[:space:]]/}" ]] && continue
        if [[ "$line" == *no_root_squash* ]]; then
            high "[kesin] no_root_squash dışa aktarımı: $f"
            detail "$line"
            found=1
        fi
    done < "$f" 2>/dev/null
    ((found))
}

check_critical_path() {
    local p="$1" f
    if [[ ! -e "$p" ]]; then
        ((VERBOSE)) && detail "Yok: $p"
        return 0
    fi
    if [[ -w "$p" ]]; then
        crit "[kesin] Yazılabilir kritik yol: $p"
    fi
    if [[ -d "$p" ]]; then
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            crit "[kesin] Yazılabilir kritik dosya: $f"
        done < <(timeout "$CMD_TIMEOUT" find "$p" -maxdepth 1 \( -type f -o -type l \) -writable 2>/dev/null)
    fi
}

# ---------------------------------------------------------------------------
# Yerleşik birim testleri
# ---------------------------------------------------------------------------
ST_FAIL=0
st_ok() {
    if "$@"; then return 0; fi
    printf 'FAIL: %s\n' "$*" >&2
    ST_FAIL=1
}
st_not() {
    if "$@"; then
        printf 'FAIL (beklenen false): %s\n' "$*" >&2
        ST_FAIL=1
    fi
}

run_selftest() {
    local saved_json_mode=$JSON_MODE
    printf 'Yerleşik testler çalışıyor...\n'
    JSON_MODE=1
    st_ok version_lt "1.2.3" "1.2.4"
    st_not version_lt "1.2.4" "1.2.3"
    st_not version_lt "1.2.3" "1.2.3"
    st_ok version_le "1.2.3" "1.2.3"
    st_ok kernel_title_matches "Linux Kernel 5.8 < 5.16.11" "5.15.0"
    st_not kernel_title_matches "Linux Kernel 2.4.0 < 4.3.6" "6.4.0"
    st_ok kernel_title_matches "Linux Kernel 2.6.0 to 2.6.26.4" "2.6.25"
    st_not kernel_title_matches "Linux Kernel 2.4/2.6" "6.4.0"
    st_ok gtfobins_has "bash"
    st_ok gtfobins_has "python3.11"
    st_not gtfobins_has "definitely-not-a-gtfobin"
    st_ok is_standard_suid_path "/usr/bin/passwd"
    st_ok is_standard_suid_path "/opt/google/chrome/chrome-sandbox"
    st_not is_standard_suid_path "/tmp/passwd"
    st_ok cron_target_is_executed "bash /home/u/x.sh" "/home/u/x.sh"
    st_not cron_target_is_executed "cat /home/u/x.sh" "/home/u/x.sh"
    st_ok cron_target_is_executed "run-parts /etc/cron.daily" "/etc/cron.daily"
    st_ok cron_target_is_executed "flock -n /tmp/lock /home/u/x.sh" "/home/u/x.sh"
    st_ok cron_target_is_executed "test -x /home/u/x.sh && /home/u/x.sh" "/home/u/x.sh"
    st_ok cron_target_is_executed "cd / && run-parts /etc/cron.daily" "/etc/cron.daily"
    st_ok cron_target_is_executed "timeout 10 /home/u/x.sh" "/home/u/x.sh"
    st_not cron_target_is_executed "flock -n /tmp/lock cat /home/u/x.sh" "/home/u/x.sh"

    local test_dir test_before test_nfs
    test_dir=$(mktemp -d "${TMPDIR:-/tmp}/lpe-selftest.XXXXXX")
    if [[ -n "$test_dir" ]]; then
        touch "$test_dir/writable"
        chmod 666 "$test_dir/writable"
        test_before=$CRIT
        check_critical_path "$test_dir"
        st_ok test "$CRIT" -gt "$test_before"

        chmod 0777 "$test_dir"
        test_before=$HIGH
        check_path_value "TESTPATH" "$test_dir"
        st_ok test "$HIGH" -gt "$test_before"

        chmod 1777 "$test_dir"
        st_ok is_sticky_dir "$test_dir"
        rm -rf -- "$test_dir"
    else
        printf 'FAIL: geçici dizin oluşturulamadı\n' >&2
        ST_FAIL=1
    fi

    test_nfs=$(mktemp "${TMPDIR:-/tmp}/lpe-nfs.XXXXXX")
    if [[ -n "$test_nfs" ]]; then
        printf '/srv/test 192.0.2.0/24(rw,no_root_squash)\n' > "$test_nfs"
        test_before=$HIGH
        check_nfs_exports_file "$test_nfs" || true
        st_ok test "$HIGH" -gt "$test_before"
        rm -f -- "$test_nfs"
    else
        printf 'FAIL: NFS test dosyası oluşturulamadı\n' >&2
        ST_FAIL=1
    fi

    JSON_MODE=$saved_json_mode
    printf 'Selftest: %s\n' "$([[ $ST_FAIL -eq 0 ]] && echo PASS || echo FAIL)"
    return "$ST_FAIL"
}

# Root oturumunda izin tabanlı kontroller yanıltıcıdır.
PERM_CHECKS=1
if ((EUID == 0)); then
    PERM_CHECKS=0
fi

# ---------------------------------------------------------------------------
# Sürüm karşılaştırma
# ---------------------------------------------------------------------------
version_lt() {
    [[ "$1" != "$2" ]] || return 1
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}

version_le() {
    [[ "$1" == "$2" ]] || version_lt "$1" "$2"
}

# Kernel exploit başlığının hedef sürümü gerçekten kapsayıp kapsamadığını denetler.
# Örn. "Linux Kernel 2.4.0 < 4.3.6" başlığı 6.4.0 için eşleşmemelidir.
kernel_title_matches() {
    local title="$1" target="$2"
    local desc tmaj tmin lo op hi

    # Açıklama kısmını ayır, parantez içindeki dağıtım sürümlerini temizle.
    desc="${title% - *}"
    desc=$(printf '%s' "$desc" | sed 's/([^)]*)//g')

    IFS=. read -r tmaj tmin _ <<< "$target"

    # "A < B", "A <= B", "A to B" biçimindeki aralıklar (birden fazla olabilir).
    local range_text range
    range_text=$(printf '%s' "$desc" \
        | grep -oE '[0-9]+(\.[0-9]+)+[[:space:]]*(<=|<|to)[[:space:]]*[0-9]+(\.[0-9]+)+')
    if [[ -n "$range_text" ]]; then
        while IFS= read -r range; do
            [[ -z "$range" ]] && continue
            [[ "$range" =~ ^([0-9]+(\.[0-9]+)+)[[:space:]]*(<=|<|to)[[:space:]]*([0-9]+(\.[0-9]+)+)$ ]] || continue
            lo="${BASH_REMATCH[1]}"
            op="${BASH_REMATCH[3]}"
            hi="${BASH_REMATCH[4]}"
            if ! version_lt "$target" "$lo"; then
                if [[ "$op" == "<" ]]; then
                    version_lt "$target" "$hi" && return 0
                else
                    version_le "$target" "$hi" && return 0
                fi
            fi
        done <<< "$range_text"
        return 1
    fi

    # Üst sınır: "< 2.6.26.4" / "<= 2.6.26.4"
    if [[ "$desc" =~ (<=|<)[[:space:]]*([0-9]+(\.[0-9]+)+) ]]; then
        op="${BASH_REMATCH[1]}"
        hi="${BASH_REMATCH[2]}"
        if [[ "$op" == "<=" ]]; then
            version_le "$target" "$hi" && return 0
        else
            version_lt "$target" "$hi" && return 0
        fi
        return 1
    fi

    # Aralık yoksa tam/prefix eşleşme: 6.4, 6.4.0, 6.4.x
    [[ "$desc" =~ (^|[^0-9.])$tmaj\.$tmin([^0-9]|$) ]] && return 0

    return 1
}

# ---------------------------------------------------------------------------
# Exploit-DB araması
#   - İnternet varsa exploit-db.com (birincil)
#   - searchsploit varsa yerel veritabanı (ek kaynak, zorunlu değil)
# ---------------------------------------------------------------------------
ONLINE_STATUS=0   # 0: bilinmiyor, 1: erişilebilir, 2: erişilemez
OFFLINE_WARNED=0

online_exploitdb() {
    local query="$1" limit="${2:-5}" raw
    have curl || return 1

    raw=$(timeout "$((CMD_TIMEOUT * 3))" curl -sS --get \
        --connect-timeout "$CMD_TIMEOUT" --max-time "$((CMD_TIMEOUT * 2))" \
        -H 'X-Requested-With: XMLHttpRequest' \
        -A 'Mozilla/5.0 (X11; Linux x86_64)' \
        --data-urlencode "q=$query" \
        --data 'draw=1' --data 'start=0' --data "length=$limit" \
        'https://www.exploit-db.com/search' 2>/dev/null) || return 1

    [[ "$raw" == "{"* ]] || return 1

    if have python3; then
        printf '%s' "$raw" | python3 -c '
import json, sys, html
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for item in data.get("data", []):
    desc = item.get("description") or []
    title = html.unescape(desc[1]) if len(desc) > 1 else ""
    print("{}\t{}".format(item.get("id", "?"), title))
' 2>/dev/null
    elif have jq; then
        printf '%s' "$raw" \
            | jq -r '.data[] | [(.id|tostring), (.description[1] // "")] | @tsv' 2>/dev/null
    else
        printf '%s' "$raw" \
            | grep -o '"id":"[0-9]*","description":\["[0-9]*","[^"]*"' \
            | sed 's/^"id":"\([0-9]*\)","description":\["[0-9]*","/\1\t/' \
            | sed "s/&#039;/'/g; s/&quot;/\"/g; s/&amp;/\\&/g"
    fi
    return 0
}

local_exploitdb() {
    local query="$1" limit="${2:-5}" raw
    have searchsploit || return 1

    raw=$(timeout "$((CMD_TIMEOUT * 3))" searchsploit --json "$query" 2>/dev/null) || return 1
    [[ "$raw" == "{"* ]] || return 1

    if have python3; then
        printf '%s' "$raw" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for item in data.get("RESULTS_EXPLOIT", []):
    print("{}\t{}".format(item.get("EDB-ID", "?"), item.get("Title", "")))
' 2>/dev/null
    elif have jq; then
        printf '%s' "$raw" \
            | jq -r '.RESULTS_EXPLOIT[] | [(."EDB-ID"|tostring), .Title] | @tsv' 2>/dev/null
    else
        printf '%s' "$raw" \
            | grep -o '"Title":"[^"]*","EDB-ID":"[^"]*"' \
            | sed 's/^"Title":"\([^"]*\)","EDB-ID":"\([^"]*\)"$/\2\t\1/'
    fi
    return 0
}

search_exploitdb() {
    local query="$1" limit="${2:-5}" target_version="${3:-}"
    local online="" local_res=""
    local online_ok=0 local_ok=0 count=0
    local fetch_limit=$((limit * 5))
    local id title i
    local -a ids=() titles=()
    local -A seen=()

    ((fetch_limit < 15)) && fetch_limit=15

    if ((OFFLINE)); then
        if ((OFFLINE_WARNED == 0)); then
            info "Offline mod: online Exploit-DB sorgusu atlandı."
            OFFLINE_WARNED=1
        fi
    elif [[ "$ONLINE_STATUS" != "2" ]] && have curl; then
        if online=$(online_exploitdb "$query" "$fetch_limit"); then
            ONLINE_STATUS=1
            online_ok=1
        elif [[ "$ONLINE_STATUS" == "0" ]]; then
            ONLINE_STATUS=2
        fi
    fi

    # İnternet varsa exploit-db.com, varsa yerel searchsploit de sorgulanır
    # (yerel arama sürüm aralıklarını yakalayabilir). searchsploit zorunlu değildir.
    if have searchsploit; then
        if local_res=$(local_exploitdb "$query" "$fetch_limit"); then
            local_ok=1
        fi
    fi

    if ((!online_ok && !local_ok)); then
        if ((OFFLINE)); then
            info "Offline modda searchsploit yok; Exploit-DB atlandı: \"$query\""
        else
            warn "Exploit araması yapılamadı (internet/curl veya searchsploit yok): \"$query\""
        fi
        return
    fi

    while IFS=$'\t' read -r id title; do
        [[ -z "$id" || -z "$title" ]] && continue
        if [[ -n "$target_version" ]] && ! kernel_title_matches "$title" "$target_version"; then
            continue
        fi
        [[ -n "${seen[$id]:-}" ]] && continue
        seen[$id]=1
        ids+=("$id")
        titles+=("$title")
    done <<< "$online"

    while IFS=$'\t' read -r id title; do
        [[ -z "$id" || -z "$title" ]] && continue
        if [[ -n "$target_version" ]] && ! kernel_title_matches "$title" "$target_version"; then
            continue
        fi
        [[ -n "${seen[$id]:-}" ]] && continue
        seen[$id]=1
        ids+=("$id")
        titles+=("$title")
    done <<< "$local_res"

    count=${#ids[@]}
    if ((count == 0)); then
        ok "Exploit-DB: eşleşme yok (\"$query\")"
        return
    fi

    found "[aday] Exploit-DB: $count eşleşme — \"$query\""
    for ((i = 0; i < count && i < limit; i++)); do
        detail "EDB-${ids[$i]} ${titles[$i]}"
    done
    if ((count > limit)); then
        detail "... +$((count - limit)) eşleşme daha"
    fi
}

# ---------------------------------------------------------------------------
# GTFOBins eşleşmesi
# ---------------------------------------------------------------------------
GTFOBINS_LIST="
aa-exec ab agetty alpine ansible ansible-playbook apt ar aria2c arj as ascii85
ash aspell at awk base32 base64 bash bpftrace bundle busctl bzip2 c89 cabextract
capsh cat chmod chown chroot clang column comm cp cpan cpio csvtool cupsfilter
curl cut dash date dd dhclient dialog diff dig dmsetup docker dosbox ed emacs env
eqn expand expect file find flock fmt fold gawk gcc gdb gem genisoimage gimp git
grep gtester gzip hd head hexdump highlight hping3 iconv install ionice ip ispell
jjs join jq ksh ksshell ld less lftp link logsave look lua lualatex make man mawk
more mosquitto mount msgattrib msgcat msgconv msgfilter msgmerge msguniq mv mysql
nano nasm nawk nc netcat nice nl nmap node nohup nroff nsenter od openvpn openvt
openssl pager paste perl php pidstat pr pry psql puppet python python2 python3
rake readelf red redcarpet restic rev rlwrap rsync ruby run-parts rview rvim scp
screen script sed service setarch sftp sh shred slsh socat soelim sort sqlite3
ssh start-stop-daemon stdbuf strace strings su sudo sysctl systemctl tac tail tar
task taskset tclsh tee telnet terraform tic time timeout tmux top torify toss
troff ul umount unexpand uniq unshare unzip uudecode uuencode valgrind vi view
vigr vim vimdiff vipw wc wget whiptail whois wish xargs xdotool xmodmap xmore
xpad xxd xz yarn zip zsh zsoelim
"

gtfobins_name() {
    local name="$1"
    case "$name" in
        python[0-9]*) printf 'python3' ;;
        perl[0-9]*)   printf 'perl' ;;
        gcc-[0-9]*)   printf 'gcc' ;;
        vim.*|vim-*)  printf 'vim' ;;
        *)            printf '%s' "$name" ;;
    esac
}

gtfobins_has() {
    local name lname list
    name="$1"
    lname=$(gtfobins_name "$name")
    list=" ${GTFOBINS_LIST//$'\n'/ } "
    [[ "$list" == *" $lname "* ]]
}

gtfobins_hint() {
    local name lname url
    name="$1"
    if gtfobins_has "$name"; then
        lname=$(gtfobins_name "$name")
        url="https://gtfobins.github.io/gtfobins/$lname/"
        if ((JSON_MODE)); then
            note_add detail "GTFobins: $url"
        else
            printf '         %s↳ GTFobins: %s%s\n' "$CYAN" "$url" "$RESET"
        fi
        return 0
    fi
    return 1
}

# Dağıtımlarla birlikte gelen, SUID/SGID olması olağan dosyalar.
STANDARD_SUID="
chage chfn chsh crontab dotlock.mailutils dotlockfile exim4 fusermount fusermount3
gpasswd mount mount.cifs mount.nfs newgidmap newgrp newuidmap ntfs-3g nvidia-modprobe
passwd pkexec plocate pppd rsh-redone-rlogin rsh-redone-rsh schroot snap-confine
ssh-agent ssh-keysign su sudo umount unix_chkpwd urxvt urxvtd utempter
vmware-user-suid-wrapper Xorg.wrap chrome-sandbox dbus-daemon-launch-helper
camel-lock-helper-1.2
"

is_standard_suid() {
    local name="$1" list
    case "$name" in
        VBox*|VirtualBox*|kismet_cap_*) return 0 ;;
    esac
    list=" ${STANDARD_SUID//$'\n'/ } "
    [[ "$list" == *" $name "* ]]
}

# ===========================================================================
# Başlangıç
# ===========================================================================
if ((SELFTEST)); then
    run_selftest
    exit $?
fi

check_dependencies
setup_tmpdir

if ((!JSON_MODE)); then
    printf '%s%s' "$BOLD" "$CYAN"
    printf '╔══════════════════════════════════════════════════════════════════╗\n'
    printf '║        LINUX YEREL YETKİ YÜKSELTME KONTROLCÜSÜ (LPE CHECK)       ║\n'
    printf '╚══════════════════════════════════════════════════════════════════╝\n'
    printf '%s' "$RESET"
    printf '  %sKullanıcı:%s %s@%s   %sKernel:%s %s\n' \
        "$DIM" "$RESET" "$(id -un)" "$(hostname 2>/dev/null || echo '?')" \
        "$DIM" "$RESET" "$(uname -r)"
fi

for missing_cmd in "${OPTIONAL_MISSING[@]}"; do
    info "Eksik opsiyonel komut: $missing_cmd"
done

if ((EUID == 0)); then
    warn "Root olarak çalışıyorsunuz. İzin/okunabilirlik kontrolleri atlanacak."
    warn "Gerçek sonuçlar için script'i düşük yetkili kullanıcı ile çalıştırın."
fi

# ===========================================================================
# 1) Kernel sürümü -> Exploit-DB
# ===========================================================================
if should_run 1; then
step 1 "Kernel sürümü ve Exploit-DB araması"
kernel=$(uname -r)
arch=$(uname -m)
info "Kernel: $kernel ($arch)"
kernel_mm=$(printf '%s' "$kernel" | grep -oE '^[0-9]+\.[0-9]+' | head -n1)
kernel_full=$(printf '%s' "$kernel" | grep -oE '^[0-9]+(\.[0-9]+)+' | head -n1)
if [[ -n "$kernel_mm" ]]; then
    search_exploitdb "Linux Kernel $kernel_mm" 4 "${kernel_full:-$kernel_mm}"
else
    warn "Kernel sürümü ayrıştırılamadı; Exploit-DB araması yapılmadı."
fi

# ===========================================================================
# 2) Sudo sürümü -> Exploit-DB
# ===========================================================================
fi
if should_run 2; then
step 2 "Sudo sürümü ve Exploit-DB araması"
if have sudo; then
    sudo_version=$(sudo -V 2>/dev/null | head -n1 | awk '{print $NF}')
    if [[ -n "$sudo_version" ]]; then
        info "Sudo sürümü: $sudo_version"
        search_exploitdb "sudo $sudo_version" 5

        if version_lt "$sudo_version" "1.9.5p2" && ! version_lt "$sudo_version" "1.8.2"; then
            high "[sürüm tabanlı, yama doğrulanmalı] CVE-2021-3156 (Baron Samedit) — sudo 1.8.2 - 1.9.5p1"
        fi
        if version_lt "$sudo_version" "1.8.28" && ! version_lt "$sudo_version" "1.8.0"; then
            high "[sürüm tabanlı, yama doğrulanmalı] CVE-2019-14287 — sudo 1.8.0 - 1.8.27 (Runas kısıtı atlatma)"
        fi
        if version_le "$sudo_version" "1.9.12p1" && ! version_lt "$sudo_version" "1.8.0"; then
            high "[sürüm tabanlı, yama doğrulanmalı] CVE-2023-22809 — sudo 1.8.0 - 1.9.12p1 (sudoedit)"
        fi
    else
        warn "Sudo sürümü alınamadı."
    fi
else
    warn "sudo komutu bulunamadı."
fi

# ===========================================================================
# 3) pkexec / polkit sürümü -> Exploit-DB
# ===========================================================================
fi
if should_run 3; then
step 3 "pkexec sürümü ve Exploit-DB araması"
pkexec_path=$(command -v pkexec 2>/dev/null || true)
if [[ -n "$pkexec_path" && -x "$pkexec_path" ]]; then
    pkexec_version=$(timeout "$CMD_TIMEOUT" pkexec --version 2>/dev/null | head -n1 | awk '{print $NF}')
    if [[ -n "$pkexec_version" ]]; then
        info "pkexec sürümü: $pkexec_version ($pkexec_path)"
        if [[ -u "$pkexec_path" ]]; then
            info "pkexec üzerinde SUID biti aktif."
        else
            warn "pkexec üzerinde SUID biti yok; PwnKit bu haliyle uygulanamaz."
        fi

        search_exploitdb "polkit $pkexec_version" 4

        if version_lt "$pkexec_version" "0.120"; then
            high "[sürüm tabanlı, yama doğrulanmalı] PwnKit CVE-2021-4034 — polkit < 0.120"
        fi
        if version_lt "$pkexec_version" "0.119"; then
            high "[sürüm tabanlı, yama doğrulanmalı] CVE-2021-3560 — polkit < 0.119 (D-Bus / PID yarışı)"
        fi
    else
        warn "pkexec sürümü alınamadı."
    fi
else
    warn "pkexec bulunamadı."
fi

# ===========================================================================
# 4) Sudoers dosyaları
# ===========================================================================
fi
if should_run 4; then
step 4 "Sudoers dosyaları"
if ((!PERM_CHECKS)); then
    info "Root oturumu: sudoers yazılabilirlik kontrolü atlandı (ADIM 16'da ayrıca denetlenir)."
fi

if [[ -r /etc/sudoers ]]; then
    sudoers_scan_files=(/etc/sudoers)
    while IFS= read -r sf; do
        [[ -z "$sf" ]] && continue
        # sudo, adında '.' bulunan dosyaları yok sayar; yedek/dağıtım
        # artıklarını taramaya dahil etme.
        sbase=$(basename -- "$sf")
        if [[ "$sbase" =~ ^[A-Za-z0-9_-]+$ ]]; then
            sudoers_scan_files+=("$sf")
        fi
    done < <(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)

    mapfile -t sudo_lines < <(
        grep -hE '^[[:space:]]*[^#[:space:]]' "${sudoers_scan_files[@]}" 2>/dev/null \
            | sed 's/[[:space:]]#.*$//' \
            | grep -E 'NOPASSWD|!authenticate|ALL|PASSWD|env_keep' | head -n 30
    )
    if ((${#sudo_lines[@]} == 0)); then
        ok "Belirgin sudoers kuralı bulunamadı."
    else
        info "Sudoers kuralları:"
        for line in "${sudo_lines[@]}"; do
            line=$(printf '%s' "$line" | tr -s '[:space:]' ' ')
            if [[ "$line" == *"!authenticate"* ]]; then
                high "[kesin] Kimlik doğrulaması kapalı sudo kuralı: $line"
            elif [[ "$line" == *"NOPASSWD"* ]]; then
                cmd_part=${line#*NOPASSWD:}
                if [[ "$cmd_part" == *"ALL"* ]]; then
                    high "[kesin] NOPASSWD + ALL (tam yetki): $line"
                else
                    nopass_gtf=0
                    while IFS= read -r cmd_path; do
                        [[ -z "$cmd_path" ]] && continue
                        if gtfobins_has "$(basename -- "$cmd_path")"; then
                            high "[aday] NOPASSWD + GTFOBins (${cmd_path##*/}): $line"
                            nopass_gtf=1
                            break
                        fi
                    done < <(printf '%s' "$cmd_part" | grep -oE '/[^,[:space:]]+' | sort -u)
                    ((nopass_gtf == 0)) && warn "[kesin] Komutla sınırlı NOPASSWD kuralı (manuel inceleme): $line"
                fi
            elif [[ "$line" == *"env_keep"* ]]; then
                if [[ "$line" =~ (LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|RUBYLIB|PATH) ]]; then
                    high "[kesin] Tehlikeli env_keep (kütüphane/PATH enjeksiyonu): $line"
                else
                    detail "$line"
                fi
            elif [[ "$line" == *"*"* ]]; then
                high "[aday] Wildcard içeren sudo kuralı: $line"
            elif [[ "$line" == *"ALL"* ]]; then
                high "[kesin] Tam yetki (ALL) sudo kuralı: $line"
            else
                detail "$line"
            fi
        done
    fi
else
    info "/etc/sudoers okunamıyor."
fi

# ===========================================================================
# 5) getcap
# ===========================================================================
fi
if should_run 5; then
step 5 "Dosya yetenekleri (getcap)"
if have getcap; then
    caps=$(timeout "$((CMD_TIMEOUT * 9))" getcap -r / 2>/dev/null)
    caps_rc=$?
    if ((caps_rc == 124)); then
        warn "getcap zaman aşımına uğradı; sonuçlar eksik olabilir."
    fi

    if [[ -z "$caps" ]]; then
        ok "Capability atanmış dosya bulunamadı."
    else
        cap_found=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^(.+)[[:space:]]+(cap_[^[:space:]]+)$ ]] || continue

            file="${BASH_REMATCH[1]}"
            cap="${BASH_REMATCH[2]}"
            flags="${cap##*=}"
            name=$(basename -- "$file" 2>/dev/null || printf '%s' "$file")

            # Çalıştırılamayan veya nosuid/noexec mount üzerindeki dosyalar etkisizdir.
            if [[ ! -x "$file" ]]; then
                ((VERBOSE)) && detail "$file: çalıştırılamıyor, capability etkisiz."
                continue
            fi
            if mount_has_opt "$file" nosuid; then
                ((VERBOSE)) && detail "$file: nosuid mount, capability etkisiz."
                continue
            fi
            if mount_has_opt "$file" noexec; then
                ((VERBOSE)) && detail "$file: noexec mount, capability etkisiz."
                continue
            fi

            # Yalnızca root'a götürebilen bir capability söz konusuysa
            # yazılabilirlik kritik kabul edilir (cap_net_bind_service gibi
            # düşük etkili yetenekler tek başına yükseltme sağlamaz).
            if ((PERM_CHECKS)) && [[ -w "$file" ]]; then
                case "$cap" in
                    *cap_setuid*|*cap_setgid*|*cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*|*cap_setfcap*|*cap_dac_override*|*cap_dac_read_search*|*cap_mknod*|*cap_chown*|*cap_fowner*|*cap_sys_rawio*)
                        ((cap_found == 0)) && info "Root'a götürebilen capability'ler:"
                        cap_found=1
                        crit "[kesin] Yazılabilir kritik capability dosyası: $file -> $cap"
                        continue
                        ;;
                esac
            fi

            # Dağıtımın standart yardımcıları: bilinen ve beklenen capability'ler.
            case "$file" in
                /usr/lib/snapd/snap-confine|/snap/*/usr/lib/snapd/snap-confine|\
                /usr/lib/dbus-1.0/dbus-daemon-launch-helper)
                    ((VERBOSE)) && detail "$file: dağıtımın standart capability yardımcısı ($cap)."
                    continue
                    ;;
            esac

            case "$cap" in
                *cap_setuid*|*cap_setgid*|*cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*|*cap_setfcap*|*cap_dac_override*)
                    if [[ "$flags" == *e* ]]; then
                        ((cap_found == 0)) && info "Root'a götürebilen etkin capability'ler:"
                        cap_found=1
                        crit "[kesin] $file -> $cap"
                        gtfobins_hint "$name" || true
                    elif [[ "$flags" == *p* ]]; then
                        ((cap_found == 0)) && info "Root'a götürebilen capability'ler:"
                        cap_found=1
                        warn "[aday] $file -> $cap (permitted; binary yükseltebilir)"
                    fi
                    ;;
                *cap_dac_read_search*|*cap_mknod*|*cap_chown*|*cap_fowner*|*cap_sys_rawio*)
                    if [[ "$flags" == *e* ]]; then
                        ((cap_found == 0)) && info "Root'a götürebilen etkin capability'ler:"
                        cap_found=1
                        high "[kesin] $file -> $cap"
                        gtfobins_hint "$name" || true
                    elif [[ "$flags" == *p* ]]; then
                        ((cap_found == 0)) && info "Root'a götürebilen capability'ler:"
                        cap_found=1
                        warn "[aday] $file -> $cap (permitted; binary yükseltebilir)"
                    fi
                    ;;
            esac
        done <<< "$caps"

        ((cap_found == 0)) && ok "Root'a götürebilen etkin capability bulunamadı."
    fi
else
    warn "getcap bulunamadı (libcap2-bin paketi gerekli)."
fi

# ===========================================================================
# 6) /etc/shadow okunabilirliği
# ===========================================================================
fi
if should_run 6; then
step 6 "/etc/shadow okunabilirliği"
if [[ -r /etc/shadow ]]; then
    if ((PERM_CHECKS)); then
        crit "[kesin] /etc/shadow okunabilir — parola hash'leri alınabilir."
        detail "İzinler: $(stat -c '%a %U:%G' /etc/shadow 2>/dev/null)"

        root_line=$(awk -F: '$1=="root"{print; exit}' /etc/shadow 2>/dev/null)
        root_hash=""
        [[ -n "$root_line" ]] && root_hash=$(printf '%s' "$root_line" | cut -d: -f2)
        if [[ -z "$root_line" ]]; then
            warn "root hesabı /etc/shadow içinde bulunamadı."
        elif [[ -z "$root_hash" ]]; then
            crit "[kesin] root hesabının parolası boş."
        elif [[ "$root_hash" == "!"* || "$root_hash" == "*"* ]]; then
            info "root parola hash'i kilitli."
        else
            root_alg=$(printf '%s' "$root_hash" | awk -F'$' '{print $2}')
            case "$root_alg" in
                1) root_alg="MD5" ;;
                2a|2b|2y) root_alg="bcrypt" ;;
                5) root_alg="SHA-256" ;;
                6) root_alg="SHA-512" ;;
                y) root_alg="yescrypt" ;;
                *) root_alg="${root_alg:-?}" ;;
            esac
            crit "[kesin] root parola hash'i mevcut (algoritma: $root_alg) — offline kırılabilir."
        fi

        empty_shadow=$(awk -F: '$2=="" {printf "%s%s", sep, $1; sep=", "}' /etc/shadow 2>/dev/null)
        if [[ -n "$empty_shadow" ]]; then
            crit "[kesin] Parolası boş hesap(lar): $empty_shadow"
        fi

        hash_count=$(awk -F: '$2 ~ /^\$/ {c++} END{print c+0}' /etc/shadow 2>/dev/null)
        if ((hash_count > 0)); then
            info "$hash_count hesapta parola hash'i var:"
            while IFS= read -r h; do
                detail "$h"
            done < <(awk -F: '
                $2 ~ /^\$/ {
                    split($2, a, "$")
                    alg = a[2]
                    if (alg == "1") alg = "MD5"
                    else if (alg == "2a" || alg == "2b" || alg == "2y") alg = "bcrypt"
                    else if (alg == "5") alg = "SHA-256"
                    else if (alg == "6") alg = "SHA-512"
                    else if (alg == "y") alg = "yescrypt"
                    print $1 " (" alg ")"
                }' /etc/shadow 2>/dev/null | head -n 10)
        fi
    else
        info "Root oturumu: /etc/shadow okunabilirlik kontrolü atlandı (root zaten okur)."
    fi
else
    ok "/etc/shadow okunamıyor."
fi

# ===========================================================================
# 7) /etc/passwd okunabilirliği
# ===========================================================================
fi
if should_run 7; then
step 7 "/etc/passwd okunabilirliği"
if [[ -r /etc/passwd ]]; then
    ok "/etc/passwd okunabilir."

    # Sistem hesaplarını ele; root ve normal (UID_MIN+) kullanıcıları göster.
    uid_min=$(awk '$1=="UID_MIN"{print $2; exit}' /etc/login.defs 2>/dev/null)
    [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000

    user_records=0
    while IFS=: read -r name _pw uid gid _gecos home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue

        if ((uid == 0)); then
            :
        elif ((uid >= uid_min && uid < 65534)); then
            case "$shell" in
                ""|*/nologin|*/false|*/sync|*/shutdown|*/halt) continue ;;
            esac
        else
            continue
        fi

        if ((user_records == 0)); then
            info "Root + normal kullanıcı kayıtları:"
            user_records=1
        fi
        gname=$(awk -F: -v g="$gid" '$3==g{print $1; exit}' /etc/group 2>/dev/null)
        detail "$name  UID=$uid  GID=$gid${gname:+($gname)}  $home  $shell"
    done < /etc/passwd

    extra_uid0=$(awk -F: '$3==0 && $1!="root"{printf "%s%s", sep, $1; sep=", "}' /etc/passwd)
    if [[ -n "$extra_uid0" ]]; then
        crit "root dışında UID 0 hesap(ları): $extra_uid0"
    fi

    empty_pw=$(awk -F: '$2==""{printf "%s%s", sep, $1; sep=", "}' /etc/passwd)
    if [[ -n "$empty_pw" ]]; then
        crit "Parolasız hesap(lar): $empty_pw"
    fi
else
    warn "/etc/passwd okunamıyor."
fi

# ===========================================================================
# 8) /etc/passwd yazılabilirliği
# ===========================================================================
fi
if should_run 8; then
step 8 "/etc/passwd yazılabilirliği"
if ((PERM_CHECKS)); then
    if [[ -w /etc/passwd ]]; then
        crit "/etc/passwd yazılabilir — root parolası/hesabı değiştirilebilir."
    else
        ok "/etc/passwd yazılamaz."
    fi
    if [[ -w /etc ]]; then
        crit "/etc dizini yazılabilir — /etc/passwd değiştirilebilir."
    fi
else
    info "Root oturumu: yazılabilirlik kontrolü atlandı."
fi

# ===========================================================================
# 9) /etc/shadow yazılabilirliği
# ===========================================================================
fi
if should_run 9; then
step 9 "/etc/shadow yazılabilirliği"
if ((PERM_CHECKS)); then
    if [[ -w /etc/shadow ]]; then
        crit "/etc/shadow yazılabilir — root parola hash'i değiştirilebilir."
    else
        ok "/etc/shadow yazılamaz."
    fi
else
    info "Root oturumu: yazılabilirlik kontrolü atlandı."
fi

# ===========================================================================
# 10) systemd servisleri
# ===========================================================================
fi
if should_run 10; then
step 10 "systemd servisleri"
if have systemctl; then
    suspicious=0

    if ((PERM_CHECKS)); then
        for unit_dir in /etc/systemd/system /run/systemd/system \
                        /usr/lib/systemd/system /lib/systemd/system; do
            [[ -d "$unit_dir" ]] || continue
            if [[ -w "$unit_dir" ]]; then
                crit "[kesin] Yazılabilir systemd unit dizini: $unit_dir"
                suspicious=1
            fi
        done

        while IFS= read -r unit_file; do
            [[ -z "$unit_file" ]] && continue
            crit "[kesin] Yazılabilir systemd unit/drop-in dosyası: $unit_file"
            suspicious=1
        done < <(timeout "$((CMD_TIMEOUT * 2))" find \
            /etc/systemd/system /run/systemd/system \
            /usr/lib/systemd/system /lib/systemd/system \
            -maxdepth 4 -type f \
            \( -name '*.service' -o -name '*.socket' -o -name '*.timer' \
               -o -name '*.path' -o -name '*.mount' -o -name '*.conf' \) \
            -writable 2>/dev/null)
    fi

    running_services=$(timeout "$CMD_TIMEOUT" systemctl list-units --type=service --state=running \
        --no-legend --no-pager 2>/dev/null \
        | awk '{for (i = 1; i <= NF; i++) if ($i ~ /\.service$/) {print $i; break}}')
    if [[ -z "$running_services" ]]; then
        warn "Çalışan systemd servisleri listelenemedi (systemd aktif değil olabilir)."
    else
        service_count=$(printf '%s\n' "$running_services" | grep -c .)
        info "Çalışan servis sayısı: $service_count"

        declare -A svc_seen_paths=()
        while IFS= read -r unit; do
            [[ -z "$unit" ]] && continue
            svc_seen_paths=()

            svc_user=$(timeout "$CMD_TIMEOUT" systemctl show -p User --value "$unit" 2>/dev/null)
            [[ -z "$svc_user" ]] && svc_user="root"

            # ExecStart/Pre/Post/Stop/Reload içindeki mutlak yolları denetle.
            for prop in ExecStart ExecStartPre ExecStartPost ExecStop ExecReload; do
                prop_value=$(timeout "$CMD_TIMEOUT" systemctl show -p "$prop" --value "$unit" 2>/dev/null)
                [[ -z "$prop_value" || "$prop_value" == "-" ]] && continue

                while IFS= read -r exec_path; do
                    [[ -z "$exec_path" || "$exec_path" == "-" ]] && continue
                    case "$exec_path" in
                        /dev/*|/proc/*|/sys/*) continue ;;
                    esac
                    # Aynı serviste aynı yol birden çok direktifte geçebilir;
                    # yinelenen bulgu üretmemek için yolu bir kez işle.
                    [[ -n "${svc_seen_paths[$exec_path]:-}" ]] && continue
                    svc_seen_paths["$exec_path"]=1

                    exec_writable=0
                    if ((PERM_CHECKS)) && [[ -w "$exec_path" ]]; then
                        exec_writable=1
                        if [[ "$svc_user" == "root" ]]; then
                            crit "[kesin] $unit ($prop) root olarak yazılabilir yol çalıştırıyor: $exec_path"
                        else
                            warn "[kesin] $unit ($prop) yazılabilir yol kullanıyor (User=$svc_user): $exec_path"
                        fi
                        suspicious=1
                    fi

                    # Yazılabilirlik zaten kritik/uyarı olarak raporlandıysa
                    # aynı yol için ikinci bir "kullanıcı alanı" bulgusu üretme.
                    if [[ "$svc_user" == "root" && $exec_writable -eq 0 ]]; then
                        case "$exec_path" in
                            /tmp/*|/var/tmp/*|/dev/shm/*|/home/*)
                                high "[aday] $unit root olarak kullanıcı alanından çalışıyor: $exec_path"
                                suspicious=1
                                ;;
                        esac
                    fi
                done < <(printf '%s' "$prop_value" | grep -oE '/[^ ;]+' | sort -u)
            done

            env_file=$(timeout "$CMD_TIMEOUT" systemctl show -p EnvironmentFile --value "$unit" 2>/dev/null)
            if [[ -n "$env_file" && "$env_file" != "-" ]]; then
                while IFS= read -r ef; do
                    ef="${ef#-}"
                    [[ -z "$ef" || "$ef" == "-" ]] && continue
                    case "$ef" in
                        /dev/*|/proc/*|/sys/*) continue ;;
                    esac
                    [[ -n "${svc_seen_paths[$ef]:-}" ]] && continue
                    svc_seen_paths["$ef"]=1
                    if ((PERM_CHECKS)) && [[ -w "$ef" ]]; then
                        if [[ "$svc_user" == "root" ]]; then
                            crit "[kesin] $unit EnvironmentFile yazılabilir (root servisi): $ef"
                        else
                            warn "[kesin] $unit EnvironmentFile yazılabilir (User=$svc_user): $ef"
                        fi
                        suspicious=1
                    fi
                done < <(printf '%s\n' "$env_file" | tr ' ' '\n' | grep -v '^$')
            fi
        done <<< "$running_services"
    fi

    timer_units=$(timeout "$CMD_TIMEOUT" systemctl list-units --type=timer --all --no-legend --no-pager 2>/dev/null \
        | awk '{for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) {print $i; break}}')
    path_units=$(timeout "$CMD_TIMEOUT" systemctl list-units --type=path --all --no-legend --no-pager 2>/dev/null \
        | awk '{for (i = 1; i <= NF; i++) if ($i ~ /\.path$/) {print $i; break}}')
    timer_count=$(printf '%s\n' "$timer_units" | grep -c .)
    path_count=$(printf '%s\n' "$path_units" | grep -c .)
    info "systemd timer: $timer_count, path unit: $path_count"
    if ((VERBOSE)); then
        while IFS= read -r t; do
            [[ -n "$t" ]] && detail "Timer: $t"
        done <<< "$timer_units"
        while IFS= read -r p; do
            [[ -n "$p" ]] && detail "Path unit: $p"
        done <<< "$path_units"
    fi

    ((suspicious == 0)) && ok "Yazılabilir unit, drop-in, timer/path veya servis binary'si bulunamadı."
else
    warn "systemctl bulunamadı (systemd yok)."
fi

# ===========================================================================
# 11) SUID/SGID root dosyaları -> GTFOBins
# ===========================================================================
fi
if should_run 11; then
step 11 "SUID/SGID dosyaları ve GTFOBins"
suid_listing=$(
    {
        timeout "$((CMD_TIMEOUT * 5))" find / -xdev -type f \( -perm -4000 -o -perm -2000 \) \
            -printf '%m %u:%g %p\n' 2>/dev/null
        for d in /var /usr /srv /opt /home /tmp /var/tmp /dev/shm; do
            [[ -d "$d" ]] || continue
            timeout "$((CMD_TIMEOUT * 2))" find "$d" -xdev -type f \( -perm -4000 -o -perm -2000 \) \
                -printf '%m %u:%g %p\n' 2>/dev/null
        done
    } | sort -u
)
suid_rc=$?
if ((suid_rc == 124)); then
    warn "SUID/SGID taraması zaman aşımına uğradı; sonuçlar eksik olabilir."
fi

if [[ -z "$suid_listing" ]]; then
    ok "SUID/SGID root dosyası bulunamadı."
else
    suid_count=$(printf '%s\n' "$suid_listing" | grep -c .)
    info "SUID/SGID dosya sayısı: $suid_count"
    standard_count=0
    interesting=0
    declare -A seen_bad_parents=()

    while read -r mode owner_group path; do
        [[ -z "$path" ]] && continue
        name=$(basename -- "$path")
        owner="${owner_group%%:*}"
        group="${owner_group#*:}"

        # Çalıştırılamayan dosyada SUID/SGID etkisizdir.
        if [[ ! -x "$path" ]]; then
            ((VERBOSE)) && detail "$path: çalıştırılamıyor, SUID/SGID etkisiz."
            continue
        fi

        # nosuid/noexec mount seçenekleri biti etkisiz kılar.
        if mount_has_opt "$path" nosuid; then
            ((VERBOSE)) && detail "$path: nosuid mount, SUID/SGID etkisiz."
            continue
        fi
        if mount_has_opt "$path" noexec; then
            ((VERBOSE)) && detail "$path: noexec mount, SUID/SGID etkisiz."
            continue
        fi

        # Dosya veya üst dizini yazılabilirse doğrudan kritik.
        if ((PERM_CHECKS)) && [[ -w "$path" ]]; then
            crit "[kesin] Yazılabilir SUID/SGID dosyası: $path ($mode $owner:$group)"
            interesting=1
            continue
        fi
        parent=$(dirname -- "$path")
        if ((PERM_CHECKS)) && [[ -w "$parent" ]] && ! is_sticky_dir "$parent"; then
            if [[ -z "${seen_bad_parents[$parent]:-}" ]]; then
                crit "[kesin] SUID/SGID dosyasının üst dizini yazılabilir: $path ($parent)"
                seen_bad_parents[$parent]=1
            fi
            interesting=1
        fi

        if (( (8#$mode & 04000) != 0 )); then
            if [[ "$owner" != "root" ]]; then
                high "[kesin] root dışı sahipli SUID dosyası: $path ($mode $owner:$group)"
                interesting=1
            elif is_standard_suid_path "$path" && is_standard_suid "$name"; then
                ((standard_count++))
                ((VERBOSE)) && detail "$path ($mode $owner:$group) [standart]"
            elif gtfobins_has "$name"; then
                high "[aday] GTFOBins SUID adayı: $path ($mode $owner:$group)"
                gtfobins_hint "$name" || true
                interesting=1
            else
                found "Standart dışı SUID: $path ($mode $owner:$group)"
                interesting=1
            fi
            continue
        fi

        if (( (8#$mode & 02000) != 0 )); then
            case "$group" in
                disk|docker|lxd|libvirt)
                    crit "[kesin] SGID ayrıcalıklı grup ($group): $path ($mode $owner:$group)"
                    interesting=1
                    ;;
                *)
                    # Dağıtımın standart yollarındaki standart SGID dosyaları
                    # (chage, crontab, ssh-agent, utempter vb.) beklenen durumdur.
                    if is_standard_suid_path "$path" && is_standard_suid "$name"; then
                        ((standard_count++))
                        ((VERBOSE)) && detail "$path ($mode $owner:$group) [standart SGID]"
                    elif [[ "$group" == "shadow" ]]; then
                        high "[kesin] Standart dışı SGID shadow dosyası: $path ($mode $owner:$group)"
                        interesting=1
                    else
                        found "SGID (grup: $group): $path ($mode $owner:$group)"
                        interesting=1
                    fi
                    ;;
            esac
        fi
    done <<< "$suid_listing"

    if ((standard_count > 0 && !VERBOSE)); then
        info "$standard_count standart SUID/SGID dosyası gizlendi (tam liste için -v)."
    fi
    ((interesting == 0)) && ok "Standart dışı veya GTFOBins eşleşen SUID/SGID bulunamadı."
fi

# ===========================================================================
# 12) sudo -l
# ===========================================================================
fi
if should_run 12; then
step 12 "sudo -l (parolasız, gerekirse parolalı)"
if have sudo; then
    sudo_output=$(timeout "$CMD_TIMEOUT" sudo -n -l 2>&1)
    sudo_rc=$?

    # Önce parolasız dene; parola gerekiyorsa terminal varsa bir kez parolalı sorgula.
    if ((sudo_rc != 0)) && [[ "$sudo_output" == *"password is required"* || "$sudo_output" == *"a terminal is required"* ]]; then
        if ((NO_PASSWORD)); then
            info "sudo parola istiyor; --no-password nedeniyle sorgulama atlandı."
        elif [[ -t 0 ]]; then
            read_timeout=$((CMD_TIMEOUT * 2))
            info "Parolasız sorgulama başarısız; parola ile denenecek (${read_timeout} sn içinde girin)."
            if IFS= read -r -s -t "$read_timeout" -p "[sudo] password for $(id -un): " sudo_pass; then
                printf '\n' >&2
            else
                printf '\n' >&2
                sudo_pass=""
            fi

            if [[ -n "$sudo_pass" ]]; then
                sudo_output=$(printf '%s\n' "$sudo_pass" | timeout "$((CMD_TIMEOUT * 4))" sudo -S -p '' -l 2>&1)
                sudo_rc=$?
            fi
            unset sudo_pass
        fi
    fi

    if ((sudo_rc == 0)); then
        info "Kullanıcının sudo yetkileri:"
        while IFS= read -r line; do
            [[ -n "$line" ]] && detail "$line"
        done < <(printf '%s\n' "$sudo_output" \
            | sed -n '/may run the following commands/,$p' \
            | grep -vE '^[[:space:]]*$' \
            | head -n 50)

        all_full=0
        if grep -qE '\(ALL([[:space:]]*:[[:space:]]*ALL)?\)[[:space:]]+(NOPASSWD:[[:space:]]*)?ALL' <<< "$sudo_output"; then
            high "[kesin] Tam yetki (ALL) tanımı var."
            all_full=1
        fi

        if grep -q 'NOPASSWD' <<< "$sudo_output"; then
            if ((all_full)); then
                high "[kesin] NOPASSWD + ALL: parolasız tam yetki."
            elif grep -qE 'NOPASSWD:[[:space:]]*ALL' <<< "$sudo_output"; then
                high "[kesin] NOPASSWD: ALL — parolasız tam yetki."
            else
                nopass_gtf=0
                while IFS= read -r cmd_path; do
                    [[ -z "$cmd_path" ]] && continue
                    if gtfobins_has "$(basename -- "$cmd_path")"; then
                        high "[aday] NOPASSWD + GTFOBins (${cmd_path##*/}): parolasız sudo"
                        nopass_gtf=1
                    fi
                done < <(printf '%s\n' "$sudo_output" | grep -oE '/[^,[:space:]]+' | sort -u)
                ((nopass_gtf == 0)) && warn "[kesin] Komutla sınırlı NOPASSWD kuralı (manuel inceleme)."
            fi
        fi

        # İzin verilen komutlardan GTFOBins eşleşmelerini çıkar.
        seen_gtf=0
        while IFS= read -r cmd_path; do
            [[ -z "$cmd_path" ]] && continue
            base=$(basename -- "$cmd_path")
            case "$base" in
                sudo|su|pkexec) continue ;;
            esac
            if gtfobins_has "$base"; then
                high "[aday] sudo ile GTFOBins komutu: $cmd_path"
                gtfobins_hint "$base" || true
                seen_gtf=1
                break
            fi
        done < <(printf '%s\n' "$sudo_output" | grep -oE '/[^,[:space:]]+' | sort -u)
        ((seen_gtf == 0)) && ((all_full == 0)) && detail "GTFOBins eşleşmesi yok."

        if grep -qE '(/[^,]*\*|\*[^,]*/)' <<< "$sudo_output"; then
            high "[aday] Sudo komut yolunda wildcard var (GTFOBins ile kötüye kullanım olası)."
        fi
        if grep -qE 'env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|RUBYLIB|PATH)' <<< "$sudo_output"; then
            high "[kesin] Tehlikeli env_keep (LD_PRELOAD/LD_LIBRARY_PATH/PATH): kütüphane enjeksiyonu olası."
        fi
    elif ((sudo_rc == 124)); then
        warn "sudo -l zaman aşımına uğradı."
    else
        case "$sudo_output" in
            *"not in the sudoers file"*|*"is not allowed"*)
                ok "Kullanıcının sudo yetkisi yok."
                ;;
            *"password is required"*|*"a terminal is required"*)
                if ((NO_PASSWORD)); then
                    :
                else
                    info "sudo parola istiyor; parolalı sorgulama yapılamadı."
                fi
                ;;
            *"incorrect password"*|*"Sorry, try again"*)
                warn "sudo parolası doğrulanamadı."
                ;;
            *)
                warn "sudo -l başarısız: $(printf '%s' "$sudo_output" | head -n1)"
                ;;
        esac
    fi
else
    warn "sudo komutu bulunamadı."
fi

# ===========================================================================
# 13) Cron işleri
# ===========================================================================
fi
if should_run 13; then
step 13 "Cron işleri ve zamanlayıcılar"
cron_any=0
cron_hidden=0
root_header=0

if ((PERM_CHECKS)); then
    for p in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
             /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
        [[ -e "$p" ]] || continue
        if [[ -w "$p" ]]; then
            crit "[kesin] Yazılabilir cron yolu: $p"
            cron_any=1
        fi
    done
fi

# Cron dosyalarındaki PATH tanımları, root işlerinin hangi dizinlerden komut
# aradığını etkiler.
while IFS= read -r path_line; do
    path_val=${path_line#*=}
    path_val=${path_val%%#*}
    check_path_value "cron PATH" "$path_val"
done < <(grep -rhE '^[[:space:]]*PATH[[:space:]]*=' /etc/crontab /etc/cron.d 2>/dev/null)

cron_entries=$(
    awk '
        /^[[:space:]]*#/ || NF == 0 || /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=/ { next }
        {
            if ($1 ~ /^@/) { user = $2; start = 3 }
            else           { user = $6; start = 7 }
            cmd = ""
            for (i = start; i <= NF; i++) cmd = cmd " " $i
            if (cmd != "") print user "|" FILENAME "|" cmd
        }
    ' /etc/crontab /etc/cron.d/* 2>/dev/null

    if [[ -r /etc/anacrontab ]]; then
        awk '
            /^[[:space:]]*#/ || NF == 0 || /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=/ { next }
            {
                cmd = ""
                for (i = 4; i <= NF; i++) cmd = cmd " " $i
                if (cmd != "") print "root|" FILENAME "|" cmd
            }
        ' /etc/anacrontab 2>/dev/null
    fi
)

if [[ -n "$cron_entries" ]]; then
    while IFS='|' read -r cron_user src cmd; do
        [[ -z "$cmd" ]] && continue

        # Yalnızca bilinen anacron/systemd varlık kontrol satırlarını gizle.
        case "$cmd" in
            *"/usr/sbin/anacron"*) cron_hidden=1; continue ;;
        esac
        if [[ "$cmd" =~ (test[[:space:]]+-[xe][[:space:]]+/run/systemd/system|\[[[:space:]]*!?[[:space:]]*-[de][[:space:]]+/run/systemd/system) ]]; then
            cron_hidden=1
            continue
        fi

        cron_any=1
        if [[ "$cron_user" == "root" ]]; then
            if ((root_header == 0)); then
                info "Root cron girdileri:"
                root_header=1
            fi
            detail "root@$(basename -- "$src"):$cmd"
        fi

        if ((PERM_CHECKS)); then
            while IFS= read -r target; do
                [[ -z "$target" ]] && continue
                case "$target" in
                    /dev/*|/proc/*|/sys/*) continue ;;
                esac

                if [[ -d "$target" && -w "$target" ]]; then
                    if [[ "$cron_user" == "root" ]]; then
                        if [[ "$cmd" == *"run-parts"* ]] || cron_target_is_executed "$cmd" "$target"; then
                            crit "[kesin] Root cron yazılabilir dizini çalıştırıyor: $target"
                        else
                            warn "[aday] Root cron yazılabilir dizine başvuruyor: $target"
                        fi
                    else
                        info "Kullanıcı cron yazılabilir dizin kullanıyor: $target"
                    fi
                elif [[ -f "$target" && -w "$target" ]]; then
                    if [[ "$cron_user" == "root" ]]; then
                        if cron_target_is_executed "$cmd" "$target"; then
                            crit "[kesin] Root cron yazılabilir dosyayı çalıştırıyor: $target"
                        else
                            warn "[aday] Root cron yazılabilir dosyaya başvuruyor (çalıştırma doğrulanmalı): $target"
                        fi
                    else
                        info "Kullanıcı cron yazılabilir hedef kullanıyor: $target"
                    fi
                fi

                parent=$(dirname -- "$target")
                if ((PERM_CHECKS)) && [[ -w "$parent" ]] && ! is_sticky_dir "$parent"; then
                    if [[ "$cron_user" == "root" ]]; then
                        crit "[kesin] Root cron hedefinin üst dizini yazılabilir: $target ($parent)"
                    else
                        warn "[kesin] Kullanıcı cron hedefinin üst dizini yazılabilir: $target ($parent)"
                    fi
                fi
            done < <(printf '%s' "$cmd" | grep -oE '/[^[:space:];|&<>]+' | sort -u)
        fi
    done <<< "$cron_entries"
fi

if have crontab; then
    user_cron=$(timeout "$CMD_TIMEOUT" crontab -l 2>/dev/null)
    if [[ -n "$user_cron" ]]; then
        cron_any=1
        info "Kullanıcı crontab girdileri:"
        while IFS= read -r line; do
            detail "$line"
        done < <(printf '%s\n' "$user_cron" | grep -vE '^[[:space:]]*(#|$)' | head -n 20)
    fi
fi

if ((PERM_CHECKS)); then
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        crit "[kesin] Yazılabilir cron betiği: $f"
        cron_any=1
    done < <(timeout "$((CMD_TIMEOUT * 2))" find /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
        /etc/cron.monthly /etc/cron.d -maxdepth 1 -type f -writable 2>/dev/null)
fi

if have systemctl; then
    timer_count=$(timeout "$CMD_TIMEOUT" systemctl list-timers --all --no-legend --no-pager 2>/dev/null | grep -c .)
    [[ "$timer_count" =~ ^[0-9]+$ ]] || timer_count=0
    info "systemd timer sayısı: $timer_count"
    # Yazılabilir timer/path dosyaları ADIM 10'da denetleniyor; burada
    # yalnızca sayım verilir (yinelenen kritik bulgu üretmemek için).
    ((timer_count > 0)) && cron_any=1
fi

if ((cron_any == 0)); then
    if ((cron_hidden)); then
        info "Yalnızca anacron/systemd varlık kontrol satırları bulundu."
    else
        ok "Kullanıcıya veya root'a ait cron/timer girdisi bulunamadı."
    fi
fi

# ===========================================================================
# 14) Yerel dinlenen portlar ve PID'ler
# ===========================================================================
fi
if should_run 14; then
step 14 "Yerel dinlenen portlar ve PID'ler"

report_port() {
    local proto="$1" local_addr="$2" pid="$3" pname="$4"
    local port skip key owner is_local scope msg

    [[ -z "$proto" || -z "$local_addr" ]] && return 0
    [[ "$pname" == "kdeconnectd" ]] && return 0

    port=${local_addr##*:}
    skip=0
    if [[ "$proto" == udp* ]]; then
        case "$local_addr" in
            127.*|\[::1\]:*|localhost:*) ;;
            0.0.0.0:*|\[::\]:*|\*:*)
                case "$port" in
                    53|67|68|69|111|123|137|138|161|162|500|514|520|5353|1716|1900|4500|51820) ;;
                    *) skip=1 ;;
                esac
                ;;
            *) skip=1 ;;
        esac
    fi
    ((skip)) && return 0

    key="$proto|$port|${pname:-$local_addr}|$pid"
    [[ -n "${seen_ports[$key]:-}" ]] && return 0
    seen_ports[$key]=1
    ((port_count++))
    ((shown_count++))

    is_local=0
    case "$local_addr" in
        127.*|\[::1\]:*|localhost:*) is_local=1 ;;
    esac
    ((is_local)) && ((local_count++))

    owner=""
    if [[ -n "$pid" && "$pid" != "-" && -r "/proc/$pid/status" ]]; then
        owner=$(awk '/^Uid:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null)
        owner=$(getent passwd "$owner" 2>/dev/null | cut -d: -f1)
    fi

    scope="tüm arayüzler"
    ((is_local)) && scope="yerel"

    msg=$(printf '%-4s %-24s %s:%s%s [%s]' \
        "$proto" "$local_addr" "${owner:-?}" "${pname:-?}" "${pid:+($pid)}" "$scope")
    info "$msg"
}

listen_rc=0
if have ss; then
    listen_output=$(timeout "$CMD_TIMEOUT" ss -H -lntup 2>/dev/null)
    listen_rc=$?
    listen_src="ss"
elif have netstat; then
    listen_output=$(timeout "$CMD_TIMEOUT" netstat -lntup 2>/dev/null | tail -n +3)
    listen_rc=$?
    listen_src="netstat"
else
    listen_output=""
    listen_src=""
    warn "ss/netstat bulunamadı; port kontrolü atlandı."
fi

if ((listen_rc != 0)); then
    warn "$listen_src portları okunamadı (çıkış kodu: $listen_rc); sonuçlar eksik olabilir."
elif [[ -z "$listen_output" ]]; then
    info "Dinlenen port bulunamadı."
else
    port_count=0
    shown_count=0
    local_count=0

    if [[ "$listen_src" == "ss" ]]; then
        while read -r proto state _rq _sq local_addr _peer rest; do
            [[ -z "$proto" || -z "$local_addr" ]] && continue
            [[ "$state" == "LISTEN" || "$state" == "UNCONN" ]] || continue

            pid=$(printf '%s' "$rest" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p')
            pname=$(printf '%s' "$rest" | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p')
            report_port "$proto" "$local_addr" "$pid" "$pname"
        done <<< "$listen_output"
    else
        while read -r proto _rq _sq local_addr _foreign state pid_name; do
            [[ -z "$proto" || -z "$local_addr" ]] && continue
            if [[ "$proto" == udp* ]]; then
                [[ -z "$pid_name" ]] && pid_name="$state"
                state=""
            fi
            [[ "$state" == "LISTEN" || "$proto" == udp* ]] || continue

            pid="${pid_name%%/*}"
            pname="${pid_name#*/}"
            [[ "$pid" == "$pid_name" ]] && pid=""
            [[ "$pname" == "$pid_name" ]] && pname=""
            report_port "$proto" "$local_addr" "$pid" "$pname"
        done <<< "$listen_output"
    fi

    info "Gösterilen $shown_count/$port_count port; $local_count tanesi yalnızca yerel arayüzde."
fi

# ===========================================================================
# 15) Ayrıcalıklı grup üyelikleri
# ===========================================================================
fi
if should_run 15; then
step 15 "Ayrıcalıklı grup üyelikleri"
if ((PERM_CHECKS)); then
    current_groups=$(id -Gn 2>/dev/null)
    info "Kullanıcı grupları: $current_groups"

    mapfile -t current_group_list < <(printf '%s\n' "$current_groups" | tr ' ' '\n')
    group_members() {
        local g="$1"
        if have getent; then
            getent group "$g" 2>/dev/null | cut -d: -f4
        else
            awk -F: -v g="$g" '$1==g {print $4}' /etc/group 2>/dev/null
        fi
    }
    in_current_group() {
        local g="$1" cg
        for cg in "${current_group_list[@]}"; do
            [[ "$cg" == "$g" ]] && return 0
        done
        return 1
    }

    privileged_found=0
    for g in sudo wheel adm disk docker lxd libvirt shadow root; do
        if in_current_group "$g"; then
            privileged_found=1
            case "$g" in
                docker)
                    if [[ -w /var/run/docker.sock || -w /run/docker.sock ]]; then
                        crit "[kesin] docker grubundasınız ve Docker soketi yazılabilir (root eşdeğeri)."
                    else
                        high "[kesin] docker grubundasınız (Docker soketi erişimi root eşdeğeri olabilir)."
                    fi
                    ;;
                lxd)
                    crit "[kesin] lxd grubundasınız; LXD genellikle doğrudan root eşdeğeridir."
                    ;;
                libvirt)
                    crit "[kesin] libvirt grubundasınız; libvirt soketi root eşdeğeri olabilir."
                    ;;
                disk)
                    crit "[kesin] disk grubundasınız; ham disk erişimi root eşdeğeridir."
                    ;;
                sudo|wheel)
                    found "[kesin] $g grubundasınız; sudo kurallarını ADIM 12'de doğrulayın."
                    ;;
                shadow)
                    high "[kesin] shadow grubundasınız; /etc/shadow okunabilir."
                    ;;
                root)
                    high "[kesin] root grubundasınız; root grubuna ait dosyaları değiştirebilirsiniz."
                    ;;
                adm)
                    info "[kesin] adm grubundasınız; sistem günlüklerine erişebilirsiniz."
                    ;;
            esac
        fi

        members=$(group_members "$g")
        if [[ -n "$members" ]]; then
            info "$g üyeleri: $members"
        fi
    done

    # Yaygın ayrıcalıklı soketlerin doğrudan yazılabilirliği.
    declare -A seen_sockets=()
    for sock in /var/run/docker.sock /run/docker.sock \
                /run/libvirt/libvirt-sock /var/run/libvirt/libvirt-sock \
                /var/snap/lxd/common/lxd/unix.socket /run/lxd.sock; do
        [[ -e "$sock" ]] || continue
        sock_key=$(readlink -f -- "$sock" 2>/dev/null || printf '%s' "$sock")
        [[ -n "${seen_sockets[$sock_key]:-}" ]] && continue
        seen_sockets[$sock_key]=1
        if [[ -w "$sock" ]]; then
            crit "[kesin] Yazılabilir ayrıcalıklı soket: $sock"
            privileged_found=1
        fi
    done

    ((privileged_found == 0)) && ok "Ayrıcalıklı grup üyeliği veya erişilebilir soket bulunamadı."
else
    info "Root oturumu: grup üyeliği kontrolü atlandı."
fi

# ===========================================================================
# 16) Yazılabilir kritik dosya ve dizinler
# ===========================================================================
fi
if should_run 16; then
step 16 "Yazılabilir kritik dosya ve dizinler"
if ((PERM_CHECKS)); then
    before_crit16=$CRIT
    critical_paths=(
        /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d
        /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d /etc/profile /etc/profile.d
        /etc/bash.bashrc /etc/environment /etc/pam.d /etc/logrotate.d
        /etc/apt/apt.conf.d /etc/dbus-1/system.d /etc/polkit-1/rules.d
    )
    for cp in "${critical_paths[@]}"; do
        check_critical_path "$cp"
    done
    ((CRIT == before_crit16)) && ok "Yazılabilir kritik dosya/dizin bulunamadı."
else
    info "Root oturumu: kritik dosya yazılabilirlik kontrolü atlandı."
fi

# ===========================================================================
# 17) PATH ve ortam değişkenleri
# ===========================================================================
fi
if should_run 17; then
step 17 "PATH ve ortam değişkenleri"
before_high17=$HIGH
before_warn17=$WARN
before_crit17=$CRIT

info "PATH=$PATH"
check_path_value "PATH" "$PATH"
for env_var in LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PERL5LIB; do
    check_env_path_var "$env_var"
done

if [[ -e /etc/ld.so.preload ]]; then
    info "/etc/ld.so.preload mevcut."
    if [[ -r /etc/ld.so.preload ]]; then
        while IFS= read -r preload_line; do
            [[ -n "$preload_line" ]] && detail "$preload_line"
        done < <(head -n 5 /etc/ld.so.preload 2>/dev/null)
    else
        info "/etc/ld.so.preload okunamıyor."
    fi
fi

if ((HIGH == before_high17 && WARN == before_warn17 && CRIT == before_crit17)); then
    ok "PATH/ortam değişkenlerinde belirgin risk bulunamadı."
fi

# ===========================================================================
# 18) NFS dışa aktarımları ve mount seçenekleri
# ===========================================================================
fi
if should_run 18; then
step 18 "NFS dışa aktarımları ve mount seçenekleri"
nfs_related=0

for exports_file in /etc/exports /etc/exports.d/*.exports; do
    [[ -r "$exports_file" ]] || continue
    nfs_related=1
    info "NFS exports dosyası: $exports_file"
    check_nfs_exports_file "$exports_file" || true
done

if [[ -r /etc/exports ]]; then
    :
else
    info "/etc/exports okunamıyor veya yok."
fi

if have findmnt; then
    nfs_mounts=$(timeout "$CMD_TIMEOUT" findmnt -rn -o TARGET,FSTYPE,OPTIONS -t nfs,nfs4 2>/dev/null)
else
    nfs_mounts=$(awk '$3 ~ /^nfs/ {print $2, $3, $4}' /proc/self/mounts 2>/dev/null)
fi

if [[ -n "$nfs_mounts" ]]; then
    while read -r target fstype opts; do
        [[ -z "$target" || -z "$fstype" ]] && continue
        info "NFS mount: $target ($fstype) [$opts]"
        nfs_related=1
        if [[ ",$opts," != *",nosuid,"* ]]; then
            warn "[aday] NFS mount nosuid değil: $target"
        fi
        if [[ ",$opts," != *",noexec,"* ]]; then
            info "NFS mount noexec değil: $target"
        fi
    done <<< "$nfs_mounts"
fi

((nfs_related == 0)) && ok "NFS dışa aktarımı veya mount'u bulunamadı."

fi
# ===========================================================================
# Özet
# ===========================================================================
if ((JSON_MODE)); then
    print_json
    exit "$(compute_exit)"
fi

printf '\n%s%s── ÖZET ──────────────────────────────────────────────────────────%s\n' \
    "$BOLD" "$CYAN" "$RESET"
printf '  %sKRİTİK:%s %d   %sYÜKSEK:%s %d   %sUYARI:%s %d   %sBULGU:%s %d\n' \
    "$ON_RED" "$RESET" "$CRIT" \
    "$RED" "$RESET" "$HIGH" \
    "$YELLOW" "$RESET" "$WARN" \
    "$MAGENTA" "$RESET" "$FOUND"

if ((CRIT > 0)); then
    printf '  %sÖncelik: KRİTİK bulguları inceleyin.%s\n' "$RED" "$RESET"
elif ((HIGH > 0)); then
    printf '  %sÖncelik: YÜKSEK bulguları inceleyin.%s\n' "$YELLOW" "$RESET"
elif ((WARN > 0)); then
    printf '  %sÖncelik: UYARI bulgularını inceleyin.%s\n' "$YELLOW" "$RESET"
else
    printf '  %sBelirgin kritik/yüksek/uyarı bulgusu yok.%s\n' "$GREEN" "$RESET"
fi

printf '  %sÇıkış kodu:%s %s (--fail-on=%s)\n' \
    "$DIM" "$RESET" "$(compute_exit)" "$FAIL_ON"
printf '\n'
exit "$(compute_exit)"

