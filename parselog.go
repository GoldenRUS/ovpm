package ovpm

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// clEntry reprsents a parsed entry that is present on OpenVPN
// log section CLIENT LIST.
type clEntry struct {
	CommonName     string    `json:"common_name"`
	RealAddress    string    `json:"real_address"`
	BytesReceived  uint64    `json:"bytes_received"`
	BytesSent      uint64    `json:"bytes_sent"`
	ConnectedSince time.Time `json:"connected_since"`
}

// rtEntry reprsents a parsed entry that is present on OpenVPN
// log section ROUTING TABLE.
type rtEntry struct {
	VirtualAddress string    `json:"virtual_address"`
	CommonName     string    `json:"common_name"`
	RealAddress    string    `json:"real_address"`
	LastRef        time.Time `json:"last_ref"`
}

// parseStatusLog parses the received OpenVPN status log file.
// And then returns the parsed client information.
func parseStatusLog(f io.Reader) ([]clEntry, []rtEntry) {
	// Recover any panics
	defer func() {
		if r := recover(); r != nil {
			logrus.WithField("panic", r).Error("OpenVPN log file is corrupt")
		}
	}()

	// Parsing stages.
	const stageCL int = 0
	const stageRT int = 1
	const stageFin int = 2

	// Parsing variables.
	var currStage int
	var skipFor int
	var cl []clEntry
	var rt []rtEntry

	// Scan and parse the file by dividing it into chunks.
	scanner, skipFor := bufio.NewScanner(f), 3
	for lc := 0; scanner.Scan(); lc++ {
		if skipFor > 0 {
			skipFor--
			continue
		}
		txt := scanner.Text()
		switch currStage {
		case stageCL:
			if strings.Contains(txt, "ROUTING TABLE") {
				currStage = stageRT
				skipFor = 1
				continue
			}
			dat := strings.Split(txt, ",")
			cl = append(cl, clEntry{
				CommonName:     trim(dat[0]),
				RealAddress:    trim(dat[1]),
				BytesReceived:  stoui64(trim(dat[2])),
				BytesSent:      stoui64(trim(dat[3])),
				ConnectedSince: stodt(trim(dat[4])),
			})
		case stageRT:
			if strings.Contains(txt, "GLOBAL STATS") {
				currStage = stageFin
				break
			}
			dat := strings.Split(txt, ",")
			rt = append(rt, rtEntry{
				VirtualAddress: trim(dat[0]),
				CommonName:     trim(dat[1]),
				RealAddress:    trim(dat[2]),
				LastRef:        stodt(trim(dat[3])),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	return cl, rt
}

// stoi64 converts string to uint64.
func stoui64(s string) uint64 {
	i, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		panic(err)
	}
	return uint64(i)
}

// stodt converts string to date time.
func stodt(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	// Удаляем лишние пробелы
	s = strings.TrimSpace(s)

	// Попробуем стандартные форматы в порядке вероятности использования
	formats := []string{
		"2006-01-02 15:04:05",  // Самый распространенный для логов
		"2006-01-02T15:04:05",  // ISO без зоны
		time.RFC3339,           // Полный ISO
		"02.01.2006 15:04:05",  // С точками
		"2006/01/02 15:04:05",  // Со слешами
		time.ANSIC,             // Unix формат
		"Jan _2 15:04:05 2006", // Упрощенный Unix формат
		"2006-01-02",           // Только дата
	}

	// Сначала попробуем в локальной зоне (более вероятно для логов)
	for _, format := range formats {
		if t, err := time.ParseInLocation(format, s, time.Local); err == nil {
			return t
		}
	}

	// Попробуем парсить как timestamp (число секунд с эпохи)
	if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(sec, 0)
	}

	// Попробуем парсить как timestamp с миллисекундами
	if millis, err := strconv.ParseInt(s, 10, 64); err == nil && millis > 1000000000000 {
		return time.Unix(millis/1000, (millis%1000)*1000000)
	}

	// Последняя попытка - пусть Go сам определит формат
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}

	logrus.WithField("time_string", s).Warn("Failed to parse time string")
	return time.Time{}
}

// trim will trim all leading and trailing whitespace from the s.
func trim(s string) string {
	return strings.TrimSpace(s)
}
