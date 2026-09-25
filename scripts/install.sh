#!/bin/sh
# Установка и обновление kproxyd на Keenetic с Entware.
#
#   curl -fsSL https://github.com/bifidotich/kproxyd/releases/download/latest/install.sh | sh
#       скачать с GitHub свежую сборку из main и установить (или обновить)
#   curl -fsSL .../install.sh | sh -s -- v0.2.0
#       конкретную версию
#   sh scripts/install.sh
#       из локальной папки проекта (бинарники собраны ./build.sh)
#
# Конфиг /opt/etc/kproxyd/config.json при обновлении сохраняется.
set -e
REPO=${KPROXYD_REPO:-bifidotich/kproxyd}
DEFAULT_VERSION=latest
VERSION=${1:-$DEFAULT_VERSION}

die() { echo "Ошибка: $*" >&2; exit 1; }

[ -d /opt/etc/init.d ] || die "Entware не найден (/opt/etc/init.d). Сначала установите OPKG/Entware."
[ -x /bin/ndmc ] || echo "Внимание: /bin/ndmc не найден — kproxyd не сможет читать конфигурацию Keenetic и проверять её настройку."

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
[ -n "$ARCH" ] || die "не удалось определить архитектуру (поддерживаются mipsel, mips и aarch64)."
echo "Архитектура: $ARCH"

TMP=/opt/tmp/kproxyd-install.$$
rm -rf "$TMP"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

# Локальный режим: скрипт запущен из папки проекта, рядом лежит собранный бинарник.
# При «curl | sh» $0 — это сам sh, и файлы берутся с GitHub.
SRC=""
if [ -z "$1" ]; then
    case "$0" in
        *install.sh)
            d=$(cd "$(dirname "$0")/.." 2>/dev/null && pwd) || d=""
            if [ -n "$d" ] && [ -f "$d/dist/kproxyd-$ARCH" ] && [ -f "$d/scripts/S99kproxyd" ]; then
                SRC=$d
            fi
            ;;
    esac
fi

if [ -n "$SRC" ]; then
    echo "Установка из $SRC"
    cp "$SRC/dist/kproxyd-$ARCH" "$TMP/kproxyd"
    cp "$SRC/scripts/S99kproxyd" "$SRC/scripts/uninstall.sh" "$TMP/"
else
    command -v curl >/dev/null 2>&1 || die "нужен curl: opkg update && opkg install curl ca-bundle"
    command -v sha256sum >/dev/null 2>&1 || die "нужен sha256sum: opkg update && opkg install coreutils-sha256sum"
    BASE="https://github.com/$REPO/releases/download/$VERSION"
    echo "Скачиваю $VERSION из github.com/$REPO"
    for f in "kproxyd-$ARCH" S99kproxyd uninstall.sh SHA256SUMS; do
        curl -fsSL --retry 3 --connect-timeout 20 -o "$TMP/$f" "$BASE/$f" ||
            die "не удалось скачать $BASE/$f
  нет такой версии, нет интернета или сертификатов (opkg install ca-bundle)"
    done
    # суммы проверяем только у нужных файлов; если релиз как раз перезаливается, они не сойдутся
    (
        cd "$TMP" &&
            grep -E "  (kproxyd-$ARCH|S99kproxyd|uninstall\.sh)\$" SHA256SUMS > sums &&
            [ "$(grep -c . sums)" = 3 ] &&
            sha256sum -c sums >/dev/null
    ) || die "контрольные суммы не совпали: файлы повреждены или релиз как раз обновляется — повторите через минуту"
    mv "$TMP/kproxyd-$ARCH" "$TMP/kproxyd"
fi
chmod +x "$TMP/kproxyd"
NEW=$("$TMP/kproxyd" -version 2>/dev/null) || die "новый kproxyd не запускается на этом роутере (архитектура $ARCH)"
OLD=""
[ -x /opt/sbin/kproxyd ] && OLD=$(/opt/sbin/kproxyd -version 2>/dev/null || echo "старая")

# всё скачано и проверено — только теперь останавливаем службу и заменяем файлы
[ -x /opt/etc/init.d/S99kproxyd ] && /opt/etc/init.d/S99kproxyd stop || true
mkdir -p /opt/sbin /opt/etc/kproxyd
mv -f "$TMP/kproxyd" /opt/sbin/kproxyd
cp "$TMP/S99kproxyd" /opt/etc/init.d/S99kproxyd
chmod +x /opt/etc/init.d/S99kproxyd
cp "$TMP/uninstall.sh" /opt/sbin/kproxyd-uninstall
chmod +x /opt/sbin/kproxyd-uninstall

# сторож теперь встроен в службу; строку от прежних версий убираем из cron
if [ -f /opt/etc/crontab ] && grep -q S99kproxyd /opt/etc/crontab; then
    sed -i '/S99kproxyd/d' /opt/etc/crontab
    [ -x /opt/etc/init.d/S10cron ] && /opt/etc/init.d/S10cron restart >/dev/null 2>&1 || true
    echo "Старый сторож kproxyd убран из cron: перезапуск при сбое теперь встроен в службу."
fi

/opt/etc/init.d/S99kproxyd start

CFG=/opt/etc/kproxyd/config.json
i=0
while [ ! -s "$CFG" ] && [ $i -lt 15 ]; do sleep 1; i=$((i + 1)); done
echo
if [ -n "$OLD" ]; then echo "kproxyd обновлён: $OLD -> $NEW"; else echo "kproxyd $NEW установлен."; fi
IP=$(ip -4 addr show br0 2>/dev/null | awk '/inet /{sub(/\/.*/, "", $2); print $2; exit}')
PORT=$(sed -n 's/.*"listen": *"[^"]*:\([0-9]*\)".*/\1/p' "$CFG" 2>/dev/null | head -1)
echo "Веб-интерфейс: http://${IP:-<адрес роутера>}:${PORT:-8088}/"
if [ -z "$OLD" ] && [ -s "$CFG" ]; then
    # раздел web идёт в конфиге первым — первые user/password принадлежат ему
    echo "Логин:  $(sed -n 's/.*"user": *"\([^"]*\)".*/\1/p' "$CFG" | head -1)"
    echo "Пароль: $(sed -n 's/.*"password": *"\([^"]*\)".*/\1/p' "$CFG" | head -1)"
else
    echo "Логин и пароль — в $CFG (раздел web)."
fi
echo
echo "Удаление: sh /opt/sbin/kproxyd-uninstall"
echo
echo "kproxyd не меняет конфигурацию Keenetic. После создания группы в веб-интерфейсе"
echo "создайте в Keenetic прокси-подключение SOCKS5 на её адрес и направьте в него списки"
echo "доменов — пошаговая инструкция показана в карточке группы."
