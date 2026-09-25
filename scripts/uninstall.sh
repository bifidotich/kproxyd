#!/bin/sh
# Удаление kproxyd с Keenetic.
#   sh scripts/uninstall.sh              удалить, конфиг kproxyd оставить
#   sh scripts/uninstall.sh --purge      удалить вместе с конфигом
#   sh scripts/uninstall.sh --dry-run    только показать, что будет сделано
#   sh scripts/uninstall.sh --keep-route маршруты route-групп оставить в текущем туннеле
#   -y                                   не спрашивать подтверждение
BIN=/opt/sbin/kproxyd
INIT=/opt/etc/init.d/S99kproxyd
CFGDIR=/opt/etc/kproxyd
CFG=$CFGDIR/config.json
FILES="$BIN $INIT /opt/var/run/kproxyd.pid /opt/var/run/kproxyd.child.pid /opt/var/log/kproxyd.log /opt/var/log/kproxyd.log.1"

PURGE="" DRY="" KEEP="" YES=""
for a in "$@"; do
    case "$a" in
        --purge) PURGE=1 ;;
        --dry-run) DRY=1 ;;
        --keep-route) KEEP=1 ;;
        -y|--yes) YES=1 ;;
        *) echo "Неизвестный параметр: $a"; sed -n '2,7p' "$0"; exit 1 ;;
    esac
done
CLEANUP_ARGS="-config $CFG -cleanup"
[ -n "$KEEP" ] && CLEANUP_ARGS="$CLEANUP_ARGS -keep-route"

manual_hint() {
    echo "Проверьте маршруты вручную:"
    echo "  ndmc -c \"show running-config\" | grep \"route object-group\""
    echo "  ndmc -c \"dns-proxy no route object-group СПИСОК ИНТЕРФЕЙС\""
    echo "  ndmc -c \"no interface Proxy0\"    # если его создавал kproxyd"
    echo "  ndmc -c \"system configuration save\""
}

# ---------- план ----------
echo "== Keenetic"
if [ -x "$BIN" ]; then
    # shellcheck disable=SC2086
    "$BIN" $CLEANUP_ARGS -dry-run || echo "  (не удалось прочитать конфигурацию Keenetic)"
else
    echo "  $BIN не найден — маршруты автоматически не убрать"
    manual_hint
fi
echo "== Файлы"
for f in $FILES; do [ -e "$f" ] && echo "  удалить $f"; done
if [ -d "$CFGDIR" ]; then
    if [ -n "$PURGE" ]; then echo "  удалить $CFGDIR (конфиг)"; else echo "  оставить $CFGDIR (конфиг; удалить: --purge)"; fi
fi
[ -f /opt/etc/crontab ] && grep -q S99kproxyd /opt/etc/crontab && echo "  убрать строку kproxyd из /opt/etc/crontab"
if [ -z "$KEEP" ]; then
    echo "После удаления домены из списков kproxyd пойдут напрямую через провайдера."
fi

[ -n "$DRY" ] && { echo "(--dry-run: ничего не изменено)"; exit 0; }
if [ -z "$YES" ]; then
    printf "Продолжить? [y/N] "
    read -r ans
    case "$ans" in y|Y|yes|да|Да) ;; *) echo "Отменено."; exit 0 ;; esac
fi

# ---------- удаление ----------
[ -x "$INIT" ] && "$INIT" stop

if [ -x "$BIN" ]; then
    echo "== Чистка Keenetic"
    # shellcheck disable=SC2086
    if ! "$BIN" $CLEANUP_ARGS; then
        echo
        echo "Не всё удалось убрать из Keenetic. kproxyd остановлен, файлы НЕ удалены —"
        echo "исправьте причину и запустите uninstall.sh ещё раз."
        manual_hint
        exit 1
    fi
fi

if [ -f /opt/etc/crontab ] && grep -q S99kproxyd /opt/etc/crontab; then
    sed -i '/S99kproxyd/d' /opt/etc/crontab
    [ -x /opt/etc/init.d/S10cron ] && /opt/etc/init.d/S10cron restart >/dev/null 2>&1
fi
# shellcheck disable=SC2086
rm -f $FILES
[ -n "$PURGE" ] && rm -rf "$CFGDIR"

echo
echo "kproxyd удалён."
[ -z "$PURGE" ] && [ -d "$CFGDIR" ] && echo "Конфиг оставлен в $CFGDIR — пригодится при переустановке."
exit 0
