package snclient

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"pkg/convert"

	cpuinfo "github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/net"
)

const (
	// SystemMetricsMeasureInterval sets the ticker measuring the CPU counter
	SystemMetricsMeasureInterval = 1 * time.Second
)

type CheckSystemHandler struct {
	noCopy noCopy

	stopChannel chan bool
	snc         *Agent

	bufferLength time.Duration
}

func NewCheckSystemHandler() Module {
	return &CheckSystemHandler{}
}

func (c *CheckSystemHandler) Defaults(_ *AgentRunSet) ConfigData {
	defaults := ConfigData{
		"default buffer length": "1h",
	}

	return defaults
}

func (c *CheckSystemHandler) Init(snc *Agent, section *ConfigSection, _ *Config, _ *AgentRunSet) error {
	c.snc = snc
	c.stopChannel = make(chan bool)

	bufferLength, _, err := section.GetDuration("default buffer length")
	if err != nil {
		return fmt.Errorf("default buffer length: %s", err.Error())
	}
	c.bufferLength = time.Duration(bufferLength) * time.Second

	// create counter
	c.update(true)

	return nil
}

func (c *CheckSystemHandler) Start() error {
	go c.mainLoop()

	return nil
}

func (c *CheckSystemHandler) Stop() {
	close(c.stopChannel)
}

func (c *CheckSystemHandler) mainLoop() {
	ticker := time.NewTicker(SystemMetricsMeasureInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChannel:
			log.Tracef("stopping CheckSystem mainLoop")

			return
		case <-ticker.C:
			c.update(false)

			continue
		}
	}
}

func (c *CheckSystemHandler) update(create bool) {
	data, times, netdata, err := c.fetch()
	if err != nil {
		log.Warnf("[CheckSystem] reading cpu info failed: %s", err.Error())

		return
	}

	if create {
		for key := range data {
			c.snc.Counter.Create("cpu", key, c.bufferLength, SystemMetricsMeasureInterval)
		}
		c.snc.Counter.Create("cpuinfo", "info", c.bufferLength, SystemMetricsMeasureInterval)
	}

	for key, val := range data {
		c.snc.Counter.Set("cpu", key, val)
	}
	c.snc.Counter.Set("cpuinfo", "info", times)

	// add interface traffic data
	for key, val := range netdata {
		if c.snc.Counter.Get("net", key) == nil {
			c.snc.Counter.Create("net", key, c.bufferLength, SystemMetricsMeasureInterval)
		}
		c.snc.Counter.Set("net", key, val)
	}

	// remove interface not updated within the bufferLength
	trimData := time.Now().Add(-c.bufferLength).UnixMilli()
	for _, key := range c.snc.Counter.Keys("net") {
		last := c.snc.Counter.Get("net", key).GetLast()
		if last.UnixMilli < trimData {
			log.Tracef("removed old net device: %s (last update: %s)", key, time.UnixMilli(last.UnixMilli).String())
			c.snc.Counter.Delete("net", key)
		}
	}

	if runtime.GOOS == "linux" {
		c.addLinuxKernelStats(create)
	}
}

func (c *CheckSystemHandler) fetch() (data map[string]float64, cputimes *cpuinfo.TimesStat, netdata map[string]float64, err error) {
	data = map[string]float64{}

	info, err := cpuinfo.Percent(0, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cpuinfo failed: %s", err.Error())
	}

	total := float64(0)
	for i, d := range info {
		data[fmt.Sprintf("core%d", i)] = d
		total += d
	}
	data["total"] = 0
	if len(info) > 0 {
		data["total"] = total / float64(len(info))
	}

	times, err := cpuinfo.Times(false)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cpuinfo failed: %s", err.Error())
	}

	netdata = map[string]float64{}
	IOList, err := net.IOCounters(true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("net.IOCounters failed: %s", err.Error())
	}

	for intnr, int := range IOList {
		netdata[int.Name+"_recv"] = float64(IOList[intnr].BytesRecv)
		netdata[int.Name+"_sent"] = float64(IOList[intnr].BytesSent)
	}

	return data, &times[0], netdata, nil
}

func (c *CheckSystemHandler) addLinuxKernelStats(create bool) {
	if create {
		c.snc.Counter.Create("kernel", "ctxt", c.bufferLength, SystemMetricsMeasureInterval)
		c.snc.Counter.Create("kernel", "processes", c.bufferLength, SystemMetricsMeasureInterval)
	}

	statFile, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer statFile.Close()
	fileScanner := bufio.NewScanner(statFile)
	for fileScanner.Scan() {
		line := fileScanner.Text()
		switch {
		case strings.HasPrefix(line, "ctxt "),
			strings.HasPrefix(line, "processes "):
			row := strings.Fields(line)
			if len(row) < 1 {
				continue
			}
			num := convert.Float64(row[1])
			c.snc.Counter.Set("kernel", row[0], num)
		}
	}
}
