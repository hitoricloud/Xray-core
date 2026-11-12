package hmc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

type destCacheKey struct {
	dest    string
	version Varint
}

type destEntry struct {
	mu                                     sync.Mutex
	keys                                   [][]byte
	serverIDs                              [2]String
	randomID                               bool
	next, lastUse                          time.Time
	probing, warned, retired               bool
	timer                                  *time.Timer
	now                                    func() time.Time
	sampleDelay, refresh, retry, retention time.Duration
}

func newDestEntry() *destEntry {
	return &destEntry{now: time.Now, sampleDelay: time.Second, refresh: time.Hour, retry: time.Minute, retention: 24 * time.Hour}
}

func destKey(dest string, version uint32) destCacheKey {
	return destCacheKey{dest, effectiveVersion(version)}
}

func (e *destEntry) addKey(key []byte) {
	for _, previous := range e.keys {
		if bytes.Equal(previous, key) {
			return
		}
	}
	e.keys = append(e.keys, bytes.Clone(key))
	if len(e.keys) > 8 {
		e.keys = e.keys[1:]
	}
}

var destKeys sync.Map

func warnDest(dest string) {
	errors.LogWarning(context.Background(), "HMC dest ", dest, " is not online-mode; HMC sessions are distinguishable")
}

var signedHexID = regexp.MustCompile(`^-?[0-9a-f]{1,16}$`)

// Rotating signed-hex ids mimic Long.toString(random, 16).
func freshServerID(sample String) String {
	if !signedHexID.MatchString(string(sample)) {
		return sample
	}
	var random [8]byte
	_, _ = rand.Read(random[:])
	return String(strconv.FormatInt(int64(binary.BigEndian.Uint64(random[:])), 16))
}

func effectiveVersion(version uint32) Varint {
	if version == 0 {
		return 775
	}
	return Varint(version)
}

func ValidateDest(dest string) error {
	host, port, err := net.SplitHostPort(dest)
	if err != nil || host == "" {
		return fmt.Errorf("invalid HMC dest: expected host:port")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("invalid HMC dest port")
	}
	return nil
}

// PrepareDest starts at most one due probe without blocking callers.
func PrepareDest(dest string, version uint32) {
	if ValidateDest(dest) != nil {
		return
	}
	key := destKey(dest, version)
	for {
		value, _ := destKeys.LoadOrStore(key, newDestEntry())
		if refreshDest(key, value.(*destEntry), true) {
			return
		}
	}
}

func refreshDest(cacheKey destCacheKey, entry *destEntry, used bool) bool {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.retired {
		return false
	}
	now := entry.now()
	if used {
		entry.lastUse = now
	}
	if now.Sub(entry.lastUse) >= entry.retention {
		entry.retired = true
		if entry.timer != nil {
			entry.timer.Stop()
			entry.timer = nil
		}
		destKeys.CompareAndDelete(cacheKey, entry)
		return false
	}
	if entry.timer != nil {
		entry.timer.Stop()
		entry.timer = nil
	}
	if entry.probing {
		armDest(cacheKey, entry)
		return true
	}
	if now.Before(entry.next) {
		armDest(cacheKey, entry)
		return true
	}
	entry.probing = true
	armDest(cacheKey, entry)
	sampleDelay := entry.sampleDelay
	go func() {
		key, id, offline, err := probeDest(cacheKey.dest, uint32(cacheKey.version))
		var key2 []byte
		id2 := id
		if err == nil {
			time.Sleep(sampleDelay)
			entry.mu.Lock()
			retired := entry.retired
			if retired {
				entry.probing = false
			}
			entry.mu.Unlock()
			if retired {
				return
			}
			var offline2 bool
			key2, id2, offline2, err = probeDest(cacheKey.dest, uint32(cacheKey.version))
			offline = offline || offline2
		}
		entry.mu.Lock()
		entry.probing = false
		if entry.retired {
			entry.mu.Unlock()
			return
		}
		delay := entry.retry
		if len(key) > 0 {
			entry.addKey(key)
			entry.serverIDs = [2]String{id, id}
			entry.randomID = false
		}
		if err == nil {
			delay = entry.refresh
			entry.addKey(key2)
			entry.serverIDs = [2]String{id, id2}
			entry.randomID = id != id2
		}
		if offline {
			entry.keys = nil
			entry.serverIDs = [2]String{}
			entry.randomID = false
		}
		entry.next = entry.now().Add(delay)
		warn := offline && !entry.warned
		entry.warned = entry.warned || offline
		if entry.timer != nil {
			entry.timer.Stop()
		}
		armDest(cacheKey, entry)
		entry.mu.Unlock()
		if warn {
			warnDest(cacheKey.dest)
		}
	}()
	return true
}

func armDest(key destCacheKey, entry *destEntry) {
	delay := entry.lastUse.Add(entry.retention).Sub(entry.now())
	if !entry.probing {
		delay = min(delay, entry.next.Sub(entry.now()))
	}
	entry.timer = time.AfterFunc(max(0, delay), func() { refreshDest(key, entry, false) })
}

func cachedDest(dest string, version uint32) ([]byte, String) {
	PrepareDest(dest, version)
	value, ok := destKeys.Load(destKey(dest, version))
	if !ok {
		return nil, ""
	}
	entry := value.(*destEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if len(entry.keys) == 0 {
		return nil, ""
	}
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(entry.keys))))
	if err != nil {
		return nil, ""
	}
	id := entry.serverIDs[0]
	if entry.randomID {
		sample, err := rand.Int(rand.Reader, big.NewInt(2))
		if err != nil {
			return nil, ""
		}
		id = freshServerID(entry.serverIDs[sample.Int64()])
	}
	return bytes.Clone(entry.keys[index.Int64()]), id
}

func probeDest(dest string, version uint32) ([]byte, String, bool, error) {
	conn, err := net.DialTimeout("tcp", dest, 5*time.Second)
	if err != nil {
		return nil, "", false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	host, port, _ := net.SplitHostPort(dest)
	number, _ := strconv.Atoi(port)
	v, address, p, state := effectiveVersion(version), String(host), UnsignedShort(number), Varint(2)
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, "", false, err
	}
	name := String(fmt.Sprintf("Hm%x", random[:4])[:9])
	uuid := UUID(random)
	uuid[6] = uuid[6]&0x0f | 0x40
	uuid[8] = uuid[8]&0x3f | 0x80
	var wire bytes.Buffer
	if err = writePacket(&wire, 0, &v, &address, &p, &state); err != nil {
		return nil, "", false, err
	}
	if err = writePacket(&wire, 0, &name, &uuid); err != nil {
		return nil, "", false, err
	}
	if err = writeFull(conn, wire.Bytes()); err != nil {
		return nil, "", false, err
	}
	packet, err := readPacket(conn)
	if err != nil {
		return nil, "", false, err
	}
	if packet.packetID != 1 {
		return nil, "", true, fmt.Errorf("dest did not send Encryption Request")
	}
	var id String
	var key, token Bytes
	if err = packet.readFields(&id, &key, &token); err != nil {
		return nil, "", false, err
	}
	if parseRSA(key) == nil {
		return nil, "", false, fmt.Errorf("invalid dest RSA SPKI")
	}
	return key, id, false, nil
}
