# Trading Hours Access Control Policy
#
# This policy restricts agent access to market trading hours only.
# Accounts for NYSE/NASDAQ hours: Monday-Friday, 9:30am-4:00pm EST.
#
# Compliance: Prevents after-hours trading system access (regulatory requirement)

package chronoguard.fintech.trading_hours

import future.keywords.if

default allow := false

# NYSE/NASDAQ trading hours: 9:30 AM - 4:00 PM EST (14:30-21:00 UTC)
trading_hours := {
    "start_hour_utc": 14,  # 9:30 AM EST = 14:30 UTC
    "start_minute": 30,
    "end_hour_utc": 21,    # 4:00 PM EST = 21:00 UTC
    "end_minute": 0,
}

# Market holidays (2025 NYSE calendar - customize yearly)
market_holidays := {
    "2025-01-01",  # New Year's Day
    "2025-01-20",  # Martin Luther King Jr. Day
    "2025-02-17",  # Presidents' Day
    "2025-04-18",  # Good Friday
    "2025-05-26",  # Memorial Day
    "2025-07-04",  # Independence Day
    "2025-09-01",  # Labor Day
    "2025-11-27",  # Thanksgiving
    "2025-12-25",  # Christmas
}

allow if {
    is_trading_day
    is_trading_hours
}

is_trading_day if {
    now_ns := time.now_ns()
    weekday := time.weekday(now_ns)

    # Monday-Friday
    weekday >= 0
    weekday <= 4

    # Not a market holiday
    date_string := time.format([now_ns, "2006-01-02", "UTC"])
    not date_string in market_holidays
}

is_trading_hours if {
    now_ns := time.now_ns()
    [hour, minute, _] := time.clock(now_ns)

    # After market open (14:30 UTC)
    time_after_open(hour, minute)

    # Before market close (21:00 UTC)
    time_before_close(hour, minute)
}

time_after_open(hour, minute) if {
    hour > trading_hours.start_hour_utc
}

time_after_open(hour, minute) if {
    hour == trading_hours.start_hour_utc
    minute >= trading_hours.start_minute
}

time_before_close(hour, minute) if {
    hour < trading_hours.end_hour_utc
}

time_before_close(hour, minute) if {
    hour == trading_hours.end_hour_utc
    minute < trading_hours.end_minute
}

deny_reason := "Access denied: Market closed (weekend)" if {
    not is_trading_day
    now_ns := time.now_ns()
    weekday := time.weekday(now_ns)
    weekday > 4
}

deny_reason := "Access denied: Market holiday" if {
    not is_trading_day
    now_ns := time.now_ns()
    date_string := time.format([now_ns, "2006-01-02", "UTC"])
    date_string in market_holidays
}

deny_reason := reason if {
    not is_trading_hours
    now_ns := time.now_ns()
    [hour, minute, _] := time.clock(now_ns)
    reason := sprintf("Access denied: Outside trading hours (current: %02d:%02d UTC)", [hour, minute])
}
