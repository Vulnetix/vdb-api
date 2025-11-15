/**
 * Shared utility functions for Hono route handlers
 * These functions provide common patterns for context handling, validation, and responses
 */

import { notifyFatalError } from './discord-error-handler'
import type { Context } from 'hono'

/**
 * Standard error response helper
 */
export const errorResponse = (c, error: unknown, defaultStatus: number = 500) => {
    if (error instanceof AuthenticationError) {
        return c.json({ ok: false, error: error.message }, 401)
    }

    if (error instanceof ValidationError) {
        return c.json({ ok: false, error: error.message }, 400)
    }

    if (error instanceof NotFoundError) {
        return c.json({ ok: false, error: error.message }, 404)
    }

    const logger = c.get('logger')
    if (logger) {
        logger.error('Unhandled error:', error)
    }
    return c.json({ ok: false, error: 'Internal Server Error' }, defaultStatus)
}

/**
 * Fatal error response helper with Discord webhook notification
 * Use this for unexpected errors that require immediate attention
 */
export const fatalErrorResponse = async (c: Context, error: unknown, defaultStatus: number = 500) => {
    // Handle known error types first (these are not considered "fatal")
    if (error instanceof AuthenticationError) {
        return c.json({ ok: false, error: error.message }, 401)
    }

    if (error instanceof ValidationError) {
        return c.json({ ok: false, error: error.message }, 400)
    }

    if (error instanceof NotFoundError) {
        return c.json({ ok: false, error: error.message }, 404)
    }

    // This is a fatal/unexpected error - notify Discord and log
    const logger = c.get('logger')
    if (logger) {
        logger.error('Fatal error:', error)
    }

    // Send Discord notification (async, won't block response)
    notifyFatalError(c, error).catch((discordError) => {
        // Don't let Discord notification errors affect the main response
        if (logger) {
            logger.warn('Discord notification failed:', discordError)
        }
    })

    const correlationId = c.get('correlationId')
    return c.json({
        ok: false,
        error: 'Internal Server Error',
        correlationId
    }, defaultStatus)
}

/**
 * Standard success response helper
 */
export const successResponse = <T>(c, data: T, status: number = 200) => {
    return c.json({ ok: true, ...data }, status)
}

/**
 * Custom error classes for better error handling
 */
export class AuthenticationError extends Error {
    constructor(message: string) {
        super(message)
        this.name = 'AuthenticationError'
    }
}

export class ValidationError extends Error {
    constructor(message: string) {
        super(message)
        this.name = 'ValidationError'
    }
}

export class NotFoundError extends Error {
    constructor(message: string) {
        super(message)
        this.name = 'NotFoundError'
    }
}
