/**
 * OpenAPI Specification Route
 * Serves the OpenAPI 3.1 specification for the VDB Manager API
 */
import type { HonoEnv } from '@worker'
import { swaggerUI } from '@hono/swagger-ui'
import { OpenAPIHono } from '@hono/zod-openapi'

// Create OpenAPI-enabled Hono app
const app = new OpenAPIHono<HonoEnv>()

/**
 * GET /v1/swagger
 * Serves Swagger UI for interactive API documentation
 */
app.get('/', swaggerUI({ url: '/v1/swagger' }))

export default app
