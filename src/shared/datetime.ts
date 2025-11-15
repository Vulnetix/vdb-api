import moment from 'moment'

export type DateLike = number | string | Date

// Normalize input to epoch milliseconds. Accepts seconds, milliseconds, ISO string, or Date.
export const normalizeEpochMs = (value: DateLike): number => {
    if (value == null) return NaN

    if (value instanceof Date) {
        return value.getTime()
    }

    if (typeof value === 'number') {
        const abs = Math.abs(value)
        if (abs >= 1e12 || `${Math.trunc(abs)}`.length >= 13) {
            return Math.trunc(value)
        }
        return Math.trunc(value * 1000)
    }

    // string
    const trimmed = value.trim()
    // numeric string
    if (/^-?\d+$/.test(trimmed)) {
        const num = parseInt(trimmed, 10)
        const abs = Math.abs(num)
        if (abs >= 1e12 || `${Math.trunc(abs)}`.length >= 13) {
            return num
        }
        return num * 1000
    }

    // ISO or other parseable date string; assume UTC input
    const m = moment.utc(trimmed)
    return m.isValid() ? m.valueOf() : NaN
}

// Normalize input to epoch seconds (integer)
export const normalizeEpochSec = (value: DateLike): number => {
    const ms = normalizeEpochMs(value)
    return Number.isFinite(ms) ? Math.floor(ms / 1000) : NaN
}

// Human-friendly absolute date: Today, Yesterday, N days ago, else locale date
export const formatFriendlyDate = (value: DateLike): string => {
    const ms = normalizeEpochMs(value)
    if (!Number.isFinite(ms)) return 'Unknown date'

    const m = moment(ms)
    const days = moment().diff(m, 'days')
    if (days === 0) return 'Today'
    if (days === 1) return 'Yesterday'
    if (days < 7) return `${days} days ago`
    return m.local().format('ll') // locale-aware, e.g., Sep 1, 2024
}

// Relative time using Moment (e.g., "3 days ago")
export const timeAgo = (value: DateLike): string => {
    const ms = normalizeEpochMs(value)
    if (!Number.isFinite(ms)) return 'Unknown date'
    return moment(ms).fromNow()
}
