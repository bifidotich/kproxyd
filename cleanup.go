package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// runCleanup убирает из Keenetic то, что настроил kproxyd: DNS-маршруты списков групп
// в интерфейсы kproxyd и Proxy-интерфейсы с описанием kproxyd-*. Вызывается из uninstall.sh
// при остановленном демоне. Возвращает код выхода процесса.
//
// keepRoute: маршруты route-групп в туннели остаются как есть (трафик списков продолжит
// идти через последний выбранный туннель, но уже без переключения).
func runCleanup(cfgPath string, dryRun, keepRoute bool) int {
	c, err := readConfigFile(cfgPath)
	if os.IsNotExist(err) {
		fmt.Printf("конфиг %s не найден — чистить в Keenetic нечего\n", cfgPath)
		return 0
	}
	if err != nil {
		fmt.Printf("ошибка: %v\n", err)
		return 1
	}
	k := newKeenetic(c.NDMC, c.RCI)
	rc, err := k.ReadConfig()
	if err != nil {
		fmt.Printf("ошибка: чтение конфигурации Keenetic: %v\n", err)
		return 1
	}

	outletIfaces := map[string]bool{}
	for _, o := range c.Outlets {
		outletIfaces[o.Iface] = true
	}
	// Proxy-интерфейсы, созданные кнопкой «Настроить Proxy в Keenetic» (description kproxyd-<группа>)
	var proxyIfaces []string
	dropIface := map[string]bool{}
	for iface, d := range rc.Descr {
		if strings.HasPrefix(d, "kproxyd-") {
			proxyIfaces = append(proxyIfaces, iface)
			dropIface[iface] = true
		}
	}
	sort.Strings(proxyIfaces)
	ourIfaces := map[string]bool{}
	for i := range outletIfaces {
		ourIfaces[i] = true
	}
	for _, g := range c.Groups {
		if g.ProxyIface != "" {
			ourIfaces[g.ProxyIface] = true
		}
	}
	for i := range dropIface {
		ourIfaces[i] = true
	}
	listMode := map[string]string{} // список -> режим группы
	for _, g := range c.Groups {
		for _, l := range g.Lists {
			listMode[l] = g.Mode
		}
	}

	var remove, keep []DNSRoute
	for _, r := range rc.Routes {
		mode, owned := listMode[r.List]
		switch {
		case dropIface[r.Iface]:
			remove = append(remove, r) // интерфейс удаляется — маршрут в него не нужен, чей бы ни был список
		case !owned || !ourIfaces[r.Iface]:
			// не наш список или ручной маршрут — не трогаем
		case keepRoute && mode == "route" && outletIfaces[r.Iface]:
			keep = append(keep, r)
		default:
			remove = append(remove, r)
		}
	}

	if len(remove) == 0 && len(proxyIfaces) == 0 {
		fmt.Println("в Keenetic нет маршрутов и интерфейсов kproxyd")
		for _, r := range keep {
			fmt.Printf("  остаётся маршрут %s -> %s\n", r.List, r.Iface)
		}
		return 0
	}
	verb := "убрать"
	if dryRun {
		verb = "будет убран"
	}
	fails := 0
	changed := false
	for _, r := range remove {
		fmt.Printf("  %s маршрут %s -> %s", verb, r.List, r.Iface)
		if dryRun {
			fmt.Println()
			continue
		}
		if err := k.RemoveRoute(r.List, r.Iface); err != nil {
			fmt.Printf(": ОШИБКА %v\n", err)
			fails++
			continue
		}
		changed = true
		fmt.Println(": готово")
	}
	for _, r := range keep {
		fmt.Printf("  остаётся маршрут %s -> %s (--keep-route)\n", r.List, r.Iface)
	}
	if dryRun {
		verb = "будет удалён"
	} else {
		verb = "удалить"
	}
	for _, i := range proxyIfaces {
		fmt.Printf("  %s интерфейс %s (%s)", verb, i, rc.Descr[i])
		if dryRun {
			fmt.Println()
			continue
		}
		if err := k.RemoveIface(i); err != nil {
			fmt.Printf(": ОШИБКА %v\n", err)
			fails++
			continue
		}
		changed = true
		fmt.Println(": готово")
	}
	if changed {
		if err := k.SaveConfig(); err != nil {
			fmt.Printf("ошибка: сохранение конфигурации Keenetic: %v\n", err)
			fails++
		} else {
			fmt.Println("конфигурация Keenetic сохранена")
		}
	}
	if fails > 0 {
		return 1
	}
	return 0
}
