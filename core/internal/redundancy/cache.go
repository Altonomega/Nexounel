package redundancy

import (
	"bytes"
	"container/list"
	"sync"
	"time"
)

// cacheEntry is one cached chunk. Data is owned by the cache: Insert
// copies, Lookup returns a copy, so callers can never mutate a stored
// chunk into a different chunk under the same id.
type cacheEntry struct {
	id           ChunkID
	data         []byte
	acked        bool
	pendingSince time.Time
}

// CacheStats is a deterministic snapshot of cache state and lifetime
// counters. Bytes is accounted bytes (stored + per-entry overhead),
// never a runtime memory measurement.
type CacheStats struct {
	Entries    int
	Bytes      int
	MaxBytes   int
	Collisions int
	Drops      int // inserts refused because no evictable entry existed
	Evictions  int
}

// Cache is a bounded LRU chunk store shared by one direction's encoder
// (sender side) or decoder (receiver side). The two roles differ in
// exactly one respect, captured by the two insert methods:
//
//   - Insert (sender): the entry starts pending (un-ACKed). Pending
//     entries are never evicted before their ACK or PendingTimeout, so
//     the sender's view of what it has introduced can never be evicted
//     out from under an in-flight frame.
//   - InsertReady (receiver): the entry is usable immediately, hence
//     evictable under plain LRU. A sender reference to an evicted chunk
//     is repaired by the miss protocol, not by cache agreement.
//
// A Cache is safe for concurrent use.
type Cache struct {
	mu         sync.Mutex
	cfg        Config
	lru        *list.List // front = most recently used, values are *cacheEntry
	byID       map[ChunkID]*list.Element
	bytes      int // accounted: sum(len(data)) + entries*entryOverheadBytes
	collisions int
	drops      int
	evictions  int
}

// NewCache builds a cache from cfg (clamped by Config.resolved).
func NewCache(cfg Config) *Cache {
	return &Cache{
		cfg:  cfg.resolved(),
		lru:  list.New(),
		byID: make(map[ChunkID]*list.Element),
	}
}

// Insert stores data as a pending (un-ACKed) sender entry and returns
// its id and whether the cache now holds exactly this content (held).
// held is false when the insert was dropped (cache full of pending
// entries) or when the id already names different content (hash
// collision): in both cases the caller must not reference the chunk.
// Inserting data already held with identical content is a no-op that
// refreshes LRU position and returns held=true.
func (c *Cache) Insert(data []byte) (ChunkID, bool) {
	return c.insert(Fingerprint(data), data, false)
}

// InsertReady stores data as an immediately usable receiver entry.
// Semantics are otherwise identical to Insert.
func (c *Cache) InsertReady(data []byte) (ChunkID, bool) {
	return c.insert(Fingerprint(data), data, true)
}

// insertID is the internal seam behind Insert/InsertReady. Tests use it
// directly with a fabricated id to exercise the collision branch, which
// cannot be reached with a real SHA-256 collision.
func (c *Cache) insertID(id ChunkID, data []byte, acked bool) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	en, held := c.insertLocked(id, data, acked)
	return en != nil, held
}

func (c *Cache) insert(id ChunkID, data []byte, acked bool) (ChunkID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, held := c.insertLocked(id, data, acked)
	return id, held
}

func (c *Cache) insertLocked(id ChunkID, data []byte, acked bool) (*cacheEntry, bool) {
	if el, ok := c.byID[id]; ok {
		en := el.Value.(*cacheEntry)
		if !bytes.Equal(en.data, data) {
			// Same id, different bytes: a hash collision. Keep the
			// first-inserted content; never cache or reference the
			// colliding chunk. Reconstruction stays byte-exact
			// because the colliding chunk travels as Raw.
			c.collisions++
			return en, false
		}
		c.lru.MoveToFront(el)
		return en, true
	}
	cost := len(data) + entryOverheadBytes
	if !c.makeRoomLocked(cost) {
		c.drops++
		return nil, false
	}
	en := &cacheEntry{id: id, data: bytes.Clone(data), acked: acked, pendingSince: c.cfg.Now()}
	c.byID[id] = c.lru.PushFront(en)
	c.bytes += cost
	return en, true
}

// makeRoomLocked evicts LRU entries until cost bytes fit and the entry
// cap allows one more entry. Pending entries younger than
// PendingTimeout are never evicted; if no evictable entry exists it
// reports false and the insert is dropped.
func (c *Cache) makeRoomLocked(cost int) bool {
	now := c.cfg.Now()
	for c.bytes+cost > c.cfg.MaxCacheBytes || c.lru.Len() >= c.cfg.MaxEntries {
		victim := c.evictableLocked(now)
		if victim == nil {
			return false
		}
		en := victim.Value.(*cacheEntry)
		c.lru.Remove(victim)
		delete(c.byID, en.id)
		c.bytes -= len(en.data) + entryOverheadBytes
		c.evictions++
	}
	return true
}

// evictableLocked returns the least-recently-used evictable entry: an
// acked entry, or a pending entry whose exemption has expired.
func (c *Cache) evictableLocked(now time.Time) *list.Element {
	for el := c.lru.Back(); el != nil; el = el.Prev() {
		en := el.Value.(*cacheEntry)
		if en.acked || !now.Before(en.pendingSince.Add(c.cfg.PendingTimeout)) {
			return el
		}
	}
	return nil
}

// Lookup returns a copy of the chunk named by id, or false. The copy
// keeps callers from mutating cached bytes.
func (c *Cache) Lookup(id ChunkID) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byID[id]
	if !ok {
		return nil, false
	}
	en := el.Value.(*cacheEntry)
	c.lru.MoveToFront(el)
	return bytes.Clone(en.data), true
}

// MarkAcked flips the named entries to acked (usable as references).
// Unknown ids are ignored; the operation is idempotent, so a
// retransmitted or coalesced ACK is harmless. It returns how many
// entries actually transitioned from pending to acked.
func (c *Cache) MarkAcked(ids []ChunkID) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, id := range ids {
		if el, ok := c.byID[id]; ok {
			en := el.Value.(*cacheEntry)
			if !en.acked {
				en.acked = true
				n++
			}
			c.lru.MoveToFront(el)
		}
	}
	return n
}

// IsAcked reports whether id is held and acked, i.e. safe to reference.
func (c *Cache) IsAcked(id ChunkID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byID[id]
	return ok && el.Value.(*cacheEntry).acked
}

// Invalidate deletes id outright (miss handling). The chunk must be
// reintroduced as a literal before it can be referenced again. It
// reports whether an entry was present.
func (c *Cache) Invalidate(id ChunkID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byID[id]
	if !ok {
		return false
	}
	en := el.Value.(*cacheEntry)
	c.lru.Remove(el)
	delete(c.byID, id)
	c.bytes -= len(en.data) + entryOverheadBytes
	return true
}

// Len returns the number of cached chunks.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// Bytes returns accounted cache bytes (stored + per-entry overhead).
// It never exceeds MaxBytes unless a single chunk is larger than the
// cap, which cannot happen: chunks are at most MaxChunkSize.
func (c *Cache) Bytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}

// Stats returns a deterministic snapshot of state and counters.
func (c *Cache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{
		Entries:    c.lru.Len(),
		Bytes:      c.bytes,
		MaxBytes:   c.cfg.MaxCacheBytes,
		Collisions: c.collisions,
		Drops:      c.drops,
		Evictions:  c.evictions,
	}
}
