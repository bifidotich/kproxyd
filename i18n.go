package main

import (
	"errors"
	"fmt"
)

// Тексты, которые видит пользователь веб-интерфейса: журнал событий, причины выбора
// подключения, сообщения о Keenetic, ошибки проверки и конфигурации. Каждый формируется
// по русскому шаблону (он же пишется в файл журнала), а английский вариант берётся из
// enFormats по тому же шаблону. Шаблона нет в таблице — английский совпадает с русским.
//
// Термины: узел (node) — группа с SOCKS5-портом; подключение (connection) — туннель Keenetic;
// соединение (session) — одно TCP-соединение клиента.
var enFormats = map[string]string{
	// журнал
	"kproxyd %s запущен": "kproxyd %s started",
	"конфигурация обновлена через веб-интерфейс":                                  "configuration updated via web interface",
	"подключение %s доступно":                                                     "connection %s is up",
	"подключение %s недоступно: %s":                                               "connection %s is down: %s",
	"подключение %s недоступно: закрыто %s":                                       "connection %s is down: closed %s",
	"узел %s: %s ⇒ %s (%s)":                                                       "node %s: %s ⇒ %s (%s)",
	"узел %s: закрыто %s через %s":                                                "node %s: closed %s via %s",
	"узел %s удалён: закрыто %s":                                                  "node %s removed: closed %s",
	"узел %s: %s больше не используется — закрыто %s":                             "node %s: %s is no longer used — closed %s",
	"узел %s: не удалось открыть %s: %v":                                          "node %s: cannot listen on %s: %v",
	"узел %s: SOCKS5 открыт на %s":                                                "node %s: SOCKS5 listening on %s",
	"узел %s: закрепление снято, выбор автоматический":                            "node %s: unpinned, automatic selection",
	"узел %s: вручную закреплено подключение %s":                                  "node %s: connection %s pinned manually",
	"узел %s: достигнут предел одновременных соединений (%d), новые отклоняются":  "node %s: concurrent session limit reached (%d), new sessions are rejected",
	"узел %s: через %s подряд не открываются разные сайты — проверяю подключение": "node %s: several sites in a row fail via %s — checking the connection",
	"чтение конфигурации Keenetic: %v":                                            "reading Keenetic configuration: %v",
	"нет доступных подключений":                                                   "no connections available",

	// причины выбора подключения
	"закреплено вручную":              "pinned manually",
	"все подключения узла недоступны": "all node connections are down",
	"разница задержек меньше порога":  "latency difference below threshold",
	"минимальная задержка %.0f мс":    "lowest latency %.0f ms",
	"по приоритету":                   "by priority",

	// проверка подключений
	"не удалось определить системное имя для %s":         "cannot determine the system device for %s",
	"устройство %s отсутствует":                          "device %s does not exist",
	"Keenetic: %s не подключено":                         "Keenetic: %s is not connected",
	"HTTP %d вместо 2xx":                                 "HTTP %d instead of 2xx",
	"DNS-сервер %s не ответил через туннель (искали %s)": "DNS server %s did not answer through the tunnel (looking up %s)",
	"DNS-сервер %s через туннель: имя %s не найдено":     "DNS server %s through the tunnel: %s not found",
	"DNS-сервер %s через туннель: %s":                    "DNS server %s through the tunnel: %s",
	"DNS роутера: имя %s не найдено":                     "router DNS: %s not found",
	"DNS роутера не ответил (искали %s)":                 "router DNS did not answer (looking up %s)",
	"DNS роутера: %s":                                    "router DNS: %s",
	"%s не ответил за %d мс":                             "%s did not answer within %d ms",
	"не удалось соединиться с %s: %s":                    "cannot connect to %s: %s",

	// Keenetic
	"подключение Keenetic %s смотрит на %s, но протокол должен быть SOCKS5":    "Keenetic connection %s points to %s, but the protocol must be SOCKS5",
	"в Keenetic нет подключения «Клиент прокси» (SOCKS5) на %s — создайте его": "Keenetic has no «Proxy client» (SOCKS5) connection to %s — create it",
	"в %s не направлен ни один список доменов — добавьте маршрут в Keenetic":   "no domain list is routed to %s — add a route in Keenetic",
	"%s → %s": "%s → %s",
	"; без «reject» у %s: если kproxyd остановится, эти домены пойдут через провайдера": "; %s without «reject»: if kproxyd stops, these domains will go through the ISP",
	"kproxyd только читает Keenetic: команда %q запрещена":                              "kproxyd only reads Keenetic: command %q is not allowed",

	// веб-интерфейс
	"неверный логин или пароль":                       "wrong username or password",
	"ndmc и rci меняются только в файле конфигурации": "ndmc and rci can only be changed in the configuration file",
	"нет такого узла":                                 "no such node",
	"нет узла %q":                                     "no node %q",

	// конфигурация
	"укажите домен без https://":                                  "specify the domain without https://",
	"недопустимый домен %q":                                       "invalid domain %q",
	"недопустимый порт %q":                                        "invalid port %q",
	"коды ответа: нужно вида 200-399 или 200,204":                 "response codes: use 200-399 or 200,204",
	"probe.dns: нужно host:port или \"system\"":                   "probe.dns: use host:port or \"system\"",
	"у подключения должны быть name и iface":                      "a connection needs name and iface",
	"подключение %q: в названии допустимы латиница, цифры, _ . -": "connection %q: the name may contain Latin letters, digits, _ . -",
	"подключение %q: недопустимое имя интерфейса %q":              "connection %q: invalid interface name %q",
	"подключение %q: недопустимое имя устройства %q":              "connection %q: invalid device name %q",
	"подключение %q указано дважды":                               "connection %q is listed twice",
	"у узла должно быть имя":                                      "a node needs a name",
	"узел %q: в названии допустимы латиница, цифры, _ . -":        "node %q: the name may contain Latin letters, digits, _ . -",
	"узел %q: режим %q больше не поддерживается — kproxyd не меняет конфигурацию Keenetic. Уберите \"mode\", задайте listen (SOCKS5) и в Keenetic направьте списки узла в прокси-подключение на этот адрес": "node %q: mode %q is no longer supported — kproxyd does not change the Keenetic configuration. Remove \"mode\", set listen (SOCKS5) and route the node's lists in Keenetic to a proxy connection to that address",
	"узел %q указан дважды":                                              "node %q is listed twice",
	"узел %q: policy должна быть fallback или fastest":                   "node %q: policy must be fallback or fastest",
	"узел %q: all_down должен быть reject или isp":                       "node %q: all_down must be reject or isp",
	"узел %q: max_conns должен быть от 1 до %d":                          "node %q: max_conns must be between 1 and %d",
	"узел %q: нет ни одного подключения":                                 "node %q: no connections",
	"узел %q: подключение %q не существует":                              "node %q: connection %q does not exist",
	"узел %q: подключение %q повторяется":                                "node %q: connection %q is repeated",
	"узел %q: закреплённое подключение %q не входит в узел":              "node %q: pinned connection %q is not in the node",
	"узел %q: неверный listen %q (нужно host:port)":                      "node %q: invalid listen %q (use host:port)",
	"узлы %q и %q слушают один адрес %s":                                 "nodes %q and %q listen on the same address %s",
	"узел %q: укажите и логин, и пароль SOCKS5, или ни того, ни другого": "node %q: set both SOCKS5 username and password, or neither",
	"узел %q: логин и пароль SOCKS5 не длиннее 255 байт":                 "node %q: SOCKS5 username and password are limited to 255 bytes",
	"узел %q: %v": "node %q: %v",
	"failover должен быть off, connect или tls":           "failover must be off, connect or tls",
	"wait_ms должен быть от 300 до 15000":                 "wait_ms must be between 300 and 15000",
	"cache_min должен быть от 1 до 1440":                  "cache_min must be between 1 and 1440",
	"watch_sec должен быть от 30 до 3600":                 "watch_sec must be between 30 and 3600",
	"watch_fails должен быть от 1 до 10":                  "watch_fails must be between 1 and 10",
	"не больше %d правил":                                 "at most %d rules",
	"правило: недопустимый домен %q":                      "rule: invalid domain %q",
	"правило %s: подключение %q не входит в узел":         "rule %s: connection %q is not in the node",
	"не больше %d проверяемых ресурсов":                   "at most %d checked resources",
	"проверка %q: %v":                                     "check %q: %v",
	"проверка %q указана дважды":                          "check %q is listed twice",
	"проверка %q: текст заглушки не длиннее 200 символов": "check %q: block page text is limited to 200 characters",
}

// Text — текст на двух языках.
type Text struct {
	Ru, En string
}

func (t Text) String() string { return t.Ru }

func (t Text) plus(o Text) Text { return Text{t.Ru + o.Ru, t.En + o.En} }

// tr подставляет аргументы в русский шаблон и его английскую пару. Аргументы-Text и ошибки
// из errf подставляются на своём языке.
func tr(format string, args ...any) Text {
	en, ok := enFormats[format]
	if !ok {
		en = format
	}
	ru, ea := make([]any, len(args)), make([]any, len(args))
	for i, a := range args {
		ru[i], ea[i] = a, a
		switch v := a.(type) {
		case Text:
			ru[i], ea[i] = v.Ru, v.En
		case error:
			var te *trError
			if errors.As(v, &te) && te == v {
				ru[i], ea[i] = te.Ru, te.En
			} else {
				ru[i], ea[i] = v.Error(), v.Error()
			}
		}
	}
	return Text{fmt.Sprintf(format, ru...), fmt.Sprintf(en, ea...)}
}

// trError — ошибка с текстом на двух языках; Error() — русский.
type trError struct{ Text }

func (e *trError) Error() string { return e.Ru }

func errf(format string, args ...any) error { return &trError{tr(format, args...)} }

// errText — текст ошибки на двух языках (обычная ошибка — одинаково на обоих).
func errText(err error) Text {
	var te *trError
	if errors.As(err, &te) && te == err {
		return te.Text
	}
	return Text{err.Error(), err.Error()}
}

// plural — «1 соединение», «2 соединения», «5 соединений».
func plural(n int, one, few, many string) string {
	m10, m100 := n%10, n%100
	switch {
	case m10 == 1 && m100 != 11:
		return fmt.Sprintf("%d %s", n, one)
	case m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14):
		return fmt.Sprintf("%d %s", n, few)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// sessions — число TCP-соединений словами на обоих языках.
func sessions(n int) Text {
	en := fmt.Sprintf("%d sessions", n)
	if n == 1 {
		en = "1 session"
	}
	return Text{plural(n, "соединение", "соединения", "соединений"), en}
}
