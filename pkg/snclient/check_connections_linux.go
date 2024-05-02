package snclient

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func (l *CheckConnections) addIPV4(_ context.Context, check *CheckData) error {
	procnet, err := l.getProcStats("/proc/net/tcp")
	if err != nil {
		return err
	}

	counter := make([]int64, tcpStateMAX-1)
	for _, sock := range procnet {
		if res, ok := check.MatchFilterMap(map[string]string{"lport": strconv.FormatUint(uint64(sock.LocalAddr.Port), 10)}); !res && ok {
			continue
		}
		if res, ok := check.MatchFilterMap(map[string]string{"rport": strconv.FormatUint(uint64(sock.RemoteAddr.Port), 10)}); !res && ok {
			continue
		}
		counter[0]++
		counter[sock.State]++
	}
	l.addEntry("ipv4", check, counter)

	return nil
}

func (l *CheckConnections) addIPV6(_ context.Context, check *CheckData) error {
	procnet, err := l.getProcStats("/proc/net/tcp6")
	if err != nil {
		return err
	}

	counter := make([]int64, tcpStateMAX-1)
	for _, sock := range procnet {
		if res, ok := check.MatchFilterMap(map[string]string{"lport": strconv.FormatUint(uint64(sock.LocalAddr.Port), 10)}); !res && ok {
			continue
		}
		if res, ok := check.MatchFilterMap(map[string]string{"rport": strconv.FormatUint(uint64(sock.RemoteAddr.Port), 10)}); !res && ok {
			continue
		}
		counter[0]++
		counter[sock.State]++
	}
	l.addEntry("ipv6", check, counter)

	return nil
}

func (l *CheckConnections) addEntry(name string, check *CheckData, counter []int64) {
	entry := l.defaultEntry(name)
	for i := range counter {
		s := tcpStates(i)
		entry[s.String()] = fmt.Sprintf("%d", counter[i])
	}

	check.listData = append(check.listData, entry)
}

func parseIPv4(s string) (net.IP, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, err
	}

	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, uint32(v))

	return ip, nil
}

func parseIPv6(s string) (net.IP, error) {
	ip := make(net.IP, net.IPv6len)
	const grpLen = 4
	i, j := 0, 4
	for len(s) != 0 {
		grp := s[0:8]
		u, err := strconv.ParseUint(grp, 16, 32)
		binary.LittleEndian.PutUint32(ip[i:j], uint32(u))
		if err != nil {
			return nil, err
		}
		i, j = i+grpLen, j+grpLen
		s = s[8:]
	}
	return ip, nil
}

func parseAddr(s string) (*SockAddr, error) {
	fields := strings.Split(s, ":")
	if len(fields) < 2 {
		return nil, fmt.Errorf("not enough fields: %v", s)
	}

	var ip net.IP
	var err error

	switch len(fields[0]) {
	case ipv4StrLen:
		ip, err = parseIPv4(fields[0])
	case ipv6StrLen:
		ip, err = parseIPv6(fields[0])
	default:
		err = fmt.Errorf("bad formatted string: %v", fields[0])
	}
	if err != nil {
		return nil, err
	}
	v, err := strconv.ParseUint(fields[1], 16, 16)
	if err != nil {
		return nil, err
	}
	return &SockAddr{IP: ip, Port: uint16(v)}, nil
}

func (l *CheckConnections) getProcStats(file string) ([]SockEntry, error) {
	procFile, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open %s: %s", file, err.Error())
	}
	defer procFile.Close()

	procnet := make([]SockEntry, 0, 4)

	fileScanner := bufio.NewScanner(procFile)

	// Discard title
	fileScanner.Scan()

	for fileScanner.Scan() {
		var e SockEntry

		line := fileScanner.Text()
		fields := strings.Fields(line)

		addr, err := parseAddr(fields[1])
		if err != nil {
			log.Tracef("cannot parse local address: %s", fields[1])
			continue
		}
		e.LocalAddr = addr

		addr, err = parseAddr(fields[2])
		if err != nil {
			log.Tracef("cannot parse remote address: %s", fields[2])
			continue
		}
		e.RemoteAddr = addr

		u, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			log.Tracef("cannot parse state: %s", fields[3])
			continue
		}
		e.State = tcpStates(u)

		procnet = append(procnet, e)
	}
	return procnet, nil
}
