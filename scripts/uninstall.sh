#!/bin/sh
# Удаление kproxyd с Keenetic.
#   sh /opt/sbin/kproxyd-uninstall              удалить, конфиг kproxyd оставить
#   sh /opt/sbin/kproxyd-uninstall --purge      удалить вместе с конфигом
#   sh /opt/sbin/kproxyd-uninstall --dry-run    только показать, что будет сделано
#   -y                                          не спрашивать подтверждение
# Без установленного скрипта:
#   curl -fsSL https://github.com/bifidotich/kproxyd/releases/download/latest/uninstall.sh | sh -s -- --purge
# Конфигурацию Keenetic kproxyd не меняет, поэтому и при удалении её не трогает:
# прокси-подключение и маршруты списков в него убираются вручную.
BIN=/opt/sbin/kproxyd
INIT=/opt/etc/init.d/S99kproxyd
CFGDIR=/opt/etc/kproxyd
FILES="$BIN $INIT /opt/sbin/kproxyd-uninstall /opt/var/run/kproxyd.pid /opt/var/run/kproxyd.child.pid /opt/var/log/kproxyd.log /opt/var/log/kproxyd.log.1"

usage() {
    echo "Параметры: --purge (удалить и конфиг), --dry-run (только показать), -y (не спрашивать)"
}

PURGE="" DRY="" YES=""
for a in "$@"; do
    case "$a" in
        --purge) PURGE=1 ;;
        --dry-run) DRY=1 ;;
        -y|--yes) YES=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Неизвестный параметр: $a"; usage; exit 1 ;;
    esac
done

echo "== Файлы"
for f in $FILES; do [ -e "$f" ] && echo "  удалить $f"; done
if [ -d "$CFGDIR" ]; then
    if [ -n "$PURGE" ]; then echo "  удалить $CFGDIR (конфиг)"; else echo "  оставить $CFGDIR (конфиг; удалить: --purge)"; fi
fi
[ -f /opt/etc/crontab ] && grep -q S99kproxyd /opt/etc/crontab && echo "  убрать строку kproxyd из /opt/etc/crontab"

[ -n "$DRY" ] && { echo "(--dry-run: ничего не изменено)"; exit 0; }
if [ -z "$YES" ]; then
    printf "Продолжить? [y/N] "
    # спрашиваем у терминала: при «curl | sh» стандартный ввод занят самим скриптом
    if ! { read -r ans < /dev/tty; } 2>/dev/null; then
        echo
        echo "Нет терминала, чтобы спросить подтверждение. Запустите с -y."
        exit 1
    fi
    case "$ans" in y|Y|yes|да|Да) ;; *) echo "Отменено."; exit 0 ;; esac
fi

[ -x "$INIT" ] && "$INIT" stop
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
echo
echo "Keenetic kproxyd не трогал. Уберите сами прокси-подключение (SOCKS5 на 127.0.0.1)"
echo "и маршруты списков доменов в него — иначе с флагом reject эти домены перестанут"
echo "открываться, а без него пойдут через провайдера. Посмотреть маршруты:"
echo "  ndmc -c \"show running-config\" | grep \"route object-group\""
exit 0
