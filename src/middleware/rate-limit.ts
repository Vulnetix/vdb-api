/**
 * Rate Limiting and Access Logging Middleware
 * Tracks API usage, enforces rate limits, and adds rate limit headers
 */
import type { Context, Next } from 'hono'
import type { PrismaClient } from '@prisma/client'
import type { HonoEnv } from '@worker'

/**
 * Calculate next Sunday at 00:00:00 UTC (week reset time)
 */
function getNextSundayMidnight(): number {
    const now = new Date()
    const dayOfWeek = now.getUTCDay()
    const daysUntilSunday = dayOfWeek === 0 ? 7 : 7 - dayOfWeek

    const nextSunday = new Date(now)
    nextSunday.setUTCDate(now.getUTCDate() + daysUntilSunday)
    nextSunday.setUTCHours(0, 0, 0, 0)

    return Math.floor((nextSunday.getTime() - now.getTime()) / 1000)
}

/**
 * Calculate seconds until next minute
 */
function getSecondsUntilNextMinute(): number {
    const now = new Date()
    const secondsElapsed = now.getUTCSeconds()
    return 60 - secondsElapsed
}

/**
 * Get rate limit statistics for an organization
 */
async function getRateLimitStats(
    prisma: PrismaClient,
    orgId: string,
    rateLimitPerMinute: number,
    maxRequestsPerWeek: number
): Promise<{
    minuteCount: number
    weekCount: number
    remaining: number
    resetSeconds: number
    isMinuteLimited: boolean
    isWeekLimited: boolean
}> {
    const now = Math.floor(Date.now() / 1000)
    const oneMinuteAgo = now - 60
    const oneWeekAgo = now - (7 * 24 * 60 * 60)

    // Setting limit to 0 means unlimited
    const hasMinuteLimit = rateLimitPerMinute > 0
    const hasWeekLimit = maxRequestsPerWeek > 0

    // Count requests in last minute (only if minute limit is enabled)
    const minuteCount = hasMinuteLimit ? await prisma.accessLog.count({
        where: {
            orgId,
            timestamp: { gte: oneMinuteAgo }
        }
    }) : 0

    // Count requests in last week (only if week limit is enabled)
    const weekCount = hasWeekLimit ? await prisma.accessLog.count({
        where: {
            orgId,
            timestamp: { gte: oneWeekAgo }
        }
    }) : 0

    // Calculate remaining based on both limits
    const minuteRemaining = hasMinuteLimit ? Math.max(0, rateLimitPerMinute - minuteCount) : Number.MAX_SAFE_INTEGER
    const weekRemaining = hasWeekLimit ? Math.max(0, maxRequestsPerWeek - weekCount) : Number.MAX_SAFE_INTEGER
    const remaining = Math.min(minuteRemaining, weekRemaining)

    // Determine which limit is hit (only if limit is enabled)
    const isMinuteLimited = hasMinuteLimit && minuteCount >= rateLimitPerMinute
    const isWeekLimited = hasWeekLimit && weekCount >= maxRequestsPerWeek

    // Calculate reset time
    let resetSeconds: number
    if (isWeekLimited) {
        // Week limit hit - reset at next Sunday midnight
        resetSeconds = getNextSundayMidnight()
    } else {
        // Minute limit or no limit - reset at next minute
        resetSeconds = getSecondsUntilNextMinute()
    }

    return {
        minuteCount,
        weekCount,
        remaining,
        resetSeconds,
        isMinuteLimited,
        isWeekLimited
    }
}

/**
 * Rate Limiting and Access Logging Middleware
 * Must be applied after JWT authentication
 */
export async function rateLimitMiddleware(c: Context<HonoEnv>, next: Next) {
    const prisma: PrismaClient = c.get('prisma')
    const logger = c.get('logger')
    const startTime = Date.now()

    try {
        // Get organization ID from JWT
        const orgId = c.get('orgId') as string | undefined
        if (!orgId) {
            logger.warn('Rate limit middleware: No orgId in context')
            return c.json({
                success: false,
                error: 'Authentication required'
            }, 401)
        }

        // Fetch organization details
        const organization = await prisma.organization.findUnique({
            where: { uuid: orgId }
        })

        if (!organization) {
            logger.warn('Rate limit middleware: Organization not found', { orgId })
            return c.json({
                success: false,
                error: 'Organization not found'
            }, 404)
        }

        if (!organization.isActive) {
            logger.warn('Rate limit middleware: Organization is inactive', { orgId })
            return c.json({
                success: false,
                error: 'Organization is inactive'
            }, 403)
        }

        // Get rate limit statistics
        const stats = await getRateLimitStats(
            prisma,
            orgId,
            organization.rateLimitPerMinute,
            organization.maxRequestsPerWeek
        )

        // Check if rate limit exceeded
        if (stats.isMinuteLimited) {
            logger.warn('Rate limit exceeded (minute)', {
                orgId,
                orgName: organization.name,
                minuteCount: stats.minuteCount,
                limit: organization.rateLimitPerMinute
            })

            c.header('RateLimit-WeekLimit', organization.maxRequestsPerWeek === 0 ? 'unlimited' : organization.maxRequestsPerWeek.toString())
            c.header('RateLimit-MinuteLimit', organization.rateLimitPerMinute === 0 ? 'unlimited' : organization.rateLimitPerMinute.toString())
            c.header('RateLimit-Remaining', '0')
            c.header('RateLimit-Reset', stats.resetSeconds.toString())

            return c.json({
                success: false,
                error: 'Rate limit exceeded',
                details: `Too many requests. Limit: ${organization.rateLimitPerMinute} requests per minute. Try again in ${stats.resetSeconds} seconds.`
            }, 429)
        }

        if (stats.isWeekLimited) {
            logger.warn('Rate limit exceeded (week)', {
                orgId,
                orgName: organization.name,
                weekCount: stats.weekCount,
                limit: organization.maxRequestsPerWeek
            })

            c.header('RateLimit-WeekLimit', organization.maxRequestsPerWeek === 0 ? 'unlimited' : organization.maxRequestsPerWeek.toString())
            c.header('RateLimit-MinuteLimit', organization.rateLimitPerMinute === 0 ? 'unlimited' : organization.rateLimitPerMinute.toString())
            c.header('RateLimit-Remaining', '0')
            c.header('RateLimit-Reset', stats.resetSeconds.toString())

            return c.json({
                success: false,
                error: 'Weekly rate limit exceeded',
                details: `Weekly quota exceeded. Limit: ${organization.maxRequestsPerWeek} requests per week. Resets in ${Math.floor(stats.resetSeconds / 3600)} hours.`
            }, 429)
        }

        // Proceed with request
        await next()

        // Log access after request completes
        const endTime = Date.now()
        const responseTime = endTime - startTime

        const clientIp = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown'
        const userAgent = c.req.header('User-Agent') || null
        const routePath = new URL(c.req.url).pathname
        const method = c.req.method

        // Log to database (async, don't wait)
        prisma.accessLog.create({
            data: {
                orgId,
                ip: clientIp,
                userAgent,
                routePath,
                method,
                statusCode: c.res.status || 200,
                timestamp: Math.floor(Date.now() / 1000),
                responseTime
            }
        }).catch(error => {
            logger.error('Failed to log access', { error, orgId, routePath })
        })

        // Add rate limit headers to successful response
        // Use "unlimited" for 0 values, otherwise show the limit
        c.header('RateLimit-WeekLimit', organization.maxRequestsPerWeek === 0 ? 'unlimited' : organization.maxRequestsPerWeek.toString())
        c.header('RateLimit-MinuteLimit', organization.rateLimitPerMinute === 0 ? 'unlimited' : organization.rateLimitPerMinute.toString())
        c.header('RateLimit-Remaining', stats.remaining === Number.MAX_SAFE_INTEGER ? 'unlimited' : stats.remaining.toString())
        c.header('RateLimit-Reset', stats.resetSeconds.toString())

        logger.info('API request completed', {
            orgId,
            orgName: organization.name,
            routePath,
            method,
            statusCode: c.res.status,
            responseTime,
            remaining: stats.remaining
        })

    } catch (error) {
        logger.error('Rate limit middleware error', error)
        return c.json({
            success: false,
            error: 'Internal server error',
            details: error instanceof Error ? error.message : String(error)
        }, 500)
    }
}
