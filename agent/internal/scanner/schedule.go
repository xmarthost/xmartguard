package scanner

import (
	"time"
	_ "time/tzdata" // time zones even where the system has no zoneinfo
)

// DefaultScheduleTZ is the time zone of the nightly scans unless set.
const DefaultScheduleTZ = "Asia/Karachi"

// ScheduleZone is the time zone the daily and weekly scans are planned in.
func ScheduleZone(name string) *time.Location {
	if name == "" {
		name = DefaultScheduleTZ
	}
	if loc, err := time.LoadLocation(name); err == nil {
		return loc
	}
	loc, _ := time.LoadLocation(DefaultScheduleTZ)
	return loc
}
