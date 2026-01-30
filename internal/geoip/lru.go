// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 GeoIP Exporter Contributors

package geoip

import (
	"container/list"
	"sync"
)

type lruCache struct {
	mu    sync.Mutex
	cap   int
	list  *list.List
	v4map map[v4Key]*list.Element
	v6map map[v6Key]*list.Element
}

type v4Key struct {
	a [4]byte
}

type v6Key struct {
	a [16]byte
}

type entry struct {
	key interface{}
	val string
}

func newLRUCache(cap int) *lruCache {
	return &lruCache{
		cap:   cap,
		list:  list.New(),
		v4map: make(map[v4Key]*list.Element, cap/2),
		v6map: make(map[v6Key]*list.Element, cap/2),
	}
}

func (c *lruCache) getV4(k [4]byte) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := v4Key{k}
	if e, ok := c.v4map[key]; ok {
		c.list.MoveToFront(e)
		return e.Value.(*entry).val, true
	}
	return "", false
}

func (c *lruCache) putV4(k [4]byte, v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := v4Key{k}
	if e, ok := c.v4map[key]; ok {
		e.Value.(*entry).val = v
		c.list.MoveToFront(e)
		return
	}
	if c.list.Len() >= c.cap {
		old := c.list.Back()
		if old != nil {
			c.list.Remove(old)
			ent := old.Value.(*entry)
			switch kk := ent.key.(type) {
			case v4Key:
				delete(c.v4map, kk)
			case v6Key:
				delete(c.v6map, kk)
			}
		}
	}
	e := c.list.PushFront(&entry{key: key, val: v})
	c.v4map[key] = e
}

func (c *lruCache) getV6(k [16]byte) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := v6Key{k}
	if e, ok := c.v6map[key]; ok {
		c.list.MoveToFront(e)
		return e.Value.(*entry).val, true
	}
	return "", false
}

func (c *lruCache) putV6(k [16]byte, v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := v6Key{k}
	if e, ok := c.v6map[key]; ok {
		e.Value.(*entry).val = v
		c.list.MoveToFront(e)
		return
	}
	if c.list.Len() >= c.cap {
		old := c.list.Back()
		if old != nil {
			c.list.Remove(old)
			ent := old.Value.(*entry)
			switch kk := ent.key.(type) {
			case v4Key:
				delete(c.v4map, kk)
			case v6Key:
				delete(c.v6map, kk)
			}
		}
	}
	e := c.list.PushFront(&entry{key: key, val: v})
	c.v6map[key] = e
}
