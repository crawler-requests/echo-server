package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// parseLibraryJSON parses a fingerprint library in the compacted JSON contract
// written by tools/ja4dbgen (also emitted by the admin UI download): the same
// {"meta":…, "ja4":{…}} shape as the embedded data/ja4db.json.
func parseLibraryJSON(data []byte) (*dbFile, error) {
	var f dbFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("bad library JSON: %w", err)
	}
	return &f, nil
}

// parseJA4CSV imports a community JA4 fingerprint dump — the export snapshot
// format used by ja4db's public snapshots (and compatible with the JA4
// fingerprint CSV published by FoxIO):
//
//	ja4_fingerprint,application,library,user_agent_string,verified,observation_count
//
// Only the JA4 fingerprint, application label and observation count are
// meaningful to the engine; rows lacking a fingerprint are skipped.
func parseJA4CSV(data []byte) (*dbFile, error) {
	r := csv.NewReader(bufio.NewReaderSize(strings.NewReader(string(data)), 1<<20))
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("CSV: %w", err)
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	fpCol, ok := idx["ja4_fingerprint"]
	if !ok {
		if i, ok2 := idx["ja4"]; ok2 {
			fpCol = i
			ok = true
		}
	}
	appCol := idx["application"]
	cntCol := idx["observation_count"]
	if !ok {
		return nil, fmt.Errorf("CSV: no ja4_fingerprint/ja4 column in header %v", header)
	}

	var f dbFile
	f.Meta.Source = "community CSV"
	f.JA4 = map[string]*dbEntry{}
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		fp := strings.TrimSpace(row[fpCol])
		if fp == "" {
			continue
		}
		e := f.JA4[fp]
		if e == nil {
			e = &dbEntry{}
			f.JA4[fp] = e
		}
		if cntCol < len(row) {
			if n, err := strconv.ParseUint(strings.TrimSpace(row[cntCol]), 10, 64); err == nil {
				e.N += n
			}
		}
		app := ""
		if appCol < len(row) {
			app = strings.TrimSpace(row[appCol])
		}
		if app != "" {
			found := false
			for _, p := range e.Apps {
				if p.Label == app {
					p.Count++
					found = true
					break
				}
			}
			if !found {
				e.Apps = append(e.Apps, dbPair{Label: app, Count: 1})
			}
		}
	}
	if len(f.JA4) == 0 {
		return nil, fmt.Errorf("CSV: no usable fingerprint rows")
	}
	// Recompute meta counts from the merged rows.
	f.Meta.Entries = len(f.JA4)
	f.Meta.Observations = 0
	for _, e := range f.JA4 {
		f.Meta.Observations += int(e.N)
	}
	return &f, nil
}

// safeName makes a provider name safe to use as a file name: letters, digits,
// dot, underscore and dash survive; everything else becomes an underscore.
func safeName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
