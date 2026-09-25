#!/bin/sh
# Установка kproxyd на Keenetic с Entware. Запуск: sh scripts/install.sh
set -e
cd "$(dirname "$0")/.."

[ -d /opt/etc/init.d ] || { echo "Entware не найден (/opt/etc/init.d). Сначала установите OPKG/Entware."; exit 1; }
[ -x /bin/ndmc ] || echo "Внимание: /bin/ndmc не найден — управлять маршрутами Keenetic не получится."

ARCH=""
if command -v opkg >/dev/null 2>&1; then
    A=$(opkg print-architecture | awk '{print $2}')
    case "$A" in
        *aarch64*) ARCH=aarch64 ;;
        *mipsel*)  ARCH=mipsel ;;
        *mips*)    ARCH=mips ;;
    esac
fi
[ -z "$ARCH" ] && [ "$(uname -m)" = aarch64 ] && ARCH=aarch64
[ -z "$ARCH" ] && { echo "Не удалось определить архитектуру. Скопируйте подходящий dist/kproxyd-* в /opt/sbin/kproxyd вручную."; exit 1; }
[ -f "dist/kproxyd-$ARCH" ] || { echo "Нет файла dist/kproxyd-$ARCH — соберите его: ./build.sh"; exit 1; }
echo "Архитектура: $ARCH"

[ -x /opt/etc/init.d/S99kproxyd ] && /opt/etc/init.d/S99kproxyd stop || true
mkdir -p /opt/sbin /opt/etc/kproxyd
cp "dist/kproxyd-$ARCH" /opt/sbin/kproxyd
chmod +x /opt/sbin/kproxyd
cp scripts/S99kproxyd /opt/etc/init.d/S99kproxyd
chmod +x /opt/etc/init.d/S99kproxyd

# сторож теперь встроен в службу; строку от прежних версий убираем из cron
if [ -f /opt/etc/crontab ] && grep -q S99kproxyd /opt/etc/crontab; then
    sed -i '/S99kproxyd/d' /opt/etc/crontab
    [ -x /opt/etc/init.d/S10cron ] && /opt/etc/init.d/S10cron restart >/dev/null 2>&1 || true
    echo "Старый сторож kproxyd убран из cron: перезапуск при сбое теперь встроен в службу."
fi

/opt/etc/init.d/S99kproxyd start
echo
grep "вход в веб-интерфейс" /opt/var/log/kproxyd.log 2>/dev/null | tail -1 || true
echo "Веб-интерфейс: http://<адрес роутера>:8088/"
echo "Логин и пароль лежат в /opt/etc/kproxyd/config.json (раздел web)."
