package snclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/consol-monitoring/snclient/pkg/convert"
	"github.com/consol-monitoring/snclient/pkg/eventlog"
	"github.com/consol-monitoring/snclient/pkg/utils"
)

func (l *CheckEventlog) Check(_ context.Context, _ *Agent, check *CheckData, _ []Argument) (*CheckResult, error) {
	timeZone, err := time.LoadLocation(l.timeZoneStr)
	if err != nil {
		return nil, fmt.Errorf("couldn't find timezone: %s", l.timeZoneStr)
	}

	if len(l.files) == 0 {
		filenames, err2 := eventlog.GetFileNames()
		if err2 != nil {
			return nil, fmt.Errorf("wmi query failed: %s", err2.Error())
		}
		l.files = append(l.files, filenames...)
	}

	lookBack, err := utils.ExpandDuration(l.scanRange)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse scan-range: %s", err.Error())
	}
	if lookBack < 0 {
		lookBack *= -1
	}
	scanLookBack := time.Now().Add(-time.Second * time.Duration(lookBack))
	uniqueIndexList := map[string]map[string]string{}
	filterUnique := false

	switch l.uniqueIndex {
	case "", "0", "false", "no":
		l.uniqueIndex = ""
	case "1":
		filterUnique = true
		l.uniqueIndex = DefaultUniqueIndex
	default:
		filterUnique = true
	}

	for _, file := range l.files {
		log.Tracef("fetching eventlog: %s", file)
		fileEvent, err := eventlog.GetLog(file, scanLookBack)
		if err != nil {
			log.Warnf("eventlog query failed, file: %s: %s", file, err.Error())

			continue
		}

		for i := range fileEvent {
			event := fileEvent[i]
			timeWritten, _ := time.Parse(eventlog.WMIDateFormat, event.TimeWritten)
			message := event.Message
			if l.truncateMessage > 0 && len(event.Message) > l.truncateMessage {
				message = event.Message[:l.truncateMessage]
			}
			listData := map[string]string{
				"computer":  event.ComputerName,
				"file":      event.LogFile,
				"log":       event.LogFile,
				"id":        fmt.Sprintf("%d", event.EventCode),
				"level":     strings.ToLower(event.Type),
				"message":   message,
				"provider":  event.SourceName,
				"source":    event.SourceName,
				"written":   timeWritten.In(timeZone).Format("2006-01-02 15:04:05 MST"),
				"writtenTS": fmt.Sprintf("%d", timeWritten.Unix()),
			}
			if !filterUnique {
				check.listData = append(check.listData, listData)

				continue
			}

			// filter out duplicate events based on the unique-index argument
			uniqueID := ReplaceMacros(l.uniqueIndex, listData)
			log.Tracef("expanded unique filter: %s", uniqueID)
			if prevEntry, ok := uniqueIndexList[uniqueID]; ok {
				count := convert.Int64(prevEntry["_count"])
				prevEntry["_count"] = fmt.Sprintf("%d", count+1)
			} else {
				check.listData = append(check.listData, listData)
				listData["_count"] = "1"
				uniqueIndexList[uniqueID] = listData
			}
		}
	}

	return check.Finalize()
}
