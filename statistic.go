package ovpm

import (
	"log"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

var (
	globalFileWatcher *FileWatcher
	fileWatcherOnce   sync.Once
	fileWatcherMu     sync.RWMutex
)

type FileWatcher struct {
	filename    string
	watcher     *fsnotify.Watcher
	lastProcess time.Time
	debounce    time.Duration
	mu          sync.RWMutex
	data        []clEntry
	statistic   []SpeedStat
	lastUpdate  time.Time
}

type SpeedStat struct {
	commonName string
	tx         float32
	rx         float32
}

// GetFileWatcher возвращает глобальный экземпляр FileWatcher
func GetFileWatcher() *FileWatcher {
	fileWatcherMu.RLock()
	defer fileWatcherMu.RUnlock()
	return globalFileWatcher
}

// InitializeFileWatcher инициализирует глобальный FileWatcher
func InitializeFileWatcher() error {
	var initErr error
	fileWatcherOnce.Do(func() {
		fw, err := NewStatisticFileWatcher()
		if err != nil {
			initErr = err
			return
		}
		globalFileWatcher = fw
		go fw.Watch()
	})
	return initErr
}

func NewFileWatcher(filename string) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	err = watcher.Add(filename)
	if err != nil {
		return nil, err
	}

	return &FileWatcher{
		filename: filename,
		watcher:  watcher,
		debounce: 100 * time.Millisecond,
	}, nil
}

func NewStatisticFileWatcher() (*FileWatcher, error) {
	return NewFileWatcher(_DefaultStatusLogPath)
}

func (fw *FileWatcher) Watch() {
	var debounceTimer *time.Timer

	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Write == fsnotify.Write {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				debounceTimer = time.AfterFunc(fw.debounce, func() {
					fw.processFile()
				})
			}

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			log.Println("Error:", err)
		}
	}
}

func (fw *FileWatcher) processFile() {
	if time.Since(fw.lastProcess) < fw.debounce {
		return
	}
	fw.getNewValue()
	fw.lastProcess = time.Now()
}

func (fw *FileWatcher) Close() {
	err := fw.watcher.Close()
	if err != nil {
		return
	}
}

func (fw *FileWatcher) getNewValue() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	data, lastUpdate := ConnectionList()

	// Обработка первого запуска
	if fw.lastUpdate.IsZero() {
		fw.data = data
		fw.lastUpdate = lastUpdate
		return
	}

	// Расчет временного интервала
	dt := lastUpdate.Sub(fw.lastUpdate)
	if dt <= 0 {
		dt = time.Second
	}
	seconds := dt.Seconds()
	if seconds == 0 {
		seconds = 1
	}
	fw.lastUpdate = lastUpdate

	// Создаем карту старых данных для расчета дельты
	clMap := make(map[string]clEntry)
	for _, el := range fw.data {
		clMap[el.CommonName] = el
	}

	// Карта для быстрого доступа к индексам статистики
	statIndexMap := make(map[string]int)
	for i, stat := range fw.statistic {
		statIndexMap[stat.commonName] = i
	}

	// Обновляем статистику для активных пользователей
	activeUsers := make(map[string]bool)
	for _, entry := range data {
		activeUsers[entry.CommonName] = true

		var tx, rx float32
		if oldEntry, exists := clMap[entry.CommonName]; exists {
			tx = (float32(entry.BytesSent) - float32(oldEntry.BytesSent)) / float32(seconds)
			rx = (float32(entry.BytesReceived) - float32(oldEntry.BytesReceived)) / float32(seconds)
		} else {
			tx = float32(entry.BytesSent) / float32(seconds)
			rx = float32(entry.BytesReceived) / float32(seconds)
		}

		if index, exists := statIndexMap[entry.CommonName]; exists {
			fw.statistic[index].tx = tx
			fw.statistic[index].rx = rx
		} else {
			fw.statistic = append(fw.statistic, SpeedStat{
				commonName: entry.CommonName,
				tx:         tx,
				rx:         rx,
			})
		}
	}

	// Удаляем статистику для отключившихся пользователей
	i := 0
	for _, stat := range fw.statistic {
		if activeUsers[stat.commonName] {
			fw.statistic[i] = stat
			i++
		}
	}
	fw.statistic = fw.statistic[:i]

	// Обновляем данные для следующего сравнения
	fw.data = data
}

// ConnectionList returns information about user's connections to the VPN server.
func ConnectionList() (list []clEntry, lastUpdate time.Time) {

	svr := TheServer()

	// Open the status log file.
	f, err := svr.openFunc(_DefaultStatusLogPath)
	if err != nil {
		panic(err)
	}

	cl, _, lU := parseStatusLogWUpdate(f) // client list from OpenVPN status log

	return cl, lU
}

func (fw *FileWatcher) GetStatistics() []SpeedStat {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	stats := make([]SpeedStat, len(fw.statistic))
	copy(stats, fw.statistic)
	return stats
}
