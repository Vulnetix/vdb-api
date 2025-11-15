## Architecture Overview

### Core Technology Stack
- **Backend**: Cloudflare Workers (HonoX)
- **Database**: PostgreSQL (Docker) with Prisma ORM
- **Storage**: Cloudflare R2 artifacts

### Project Structure
- `api/` - HonoX Workers API endpoints
  - `api/` - API routes following directory structure (each exports Hono app)

### API Architecture
- All API endpoints are HonoX Workers in `api/`
- **Never** Use file-based routing: `[uuid].ts`. Always create dynamic `/api/:uuid` HonoX endpoints
- Each API file exports a default Hono app instance
- All routes registered in `_worker.ts` for direct routing
- Database access via `c.get('prisma')`
- Environment/bindings via `c.env`
- Route parameters via `c.req.param('paramName')`

## Code Conventions

### TypeScript Requirements
- All JavaScript must be TypeScript
- Never use `any` or `unknown` types
- Use `let`/`const`, never `var`
- Arrow functions only, no `function` keyword
- Template literals (backticks) for strings
- 4-space indentation
- Always define types explicitly for parameters and return values

## HonoX Development Patterns

### API Endpoint Template
All new API endpoints should follow this HonoX pattern:

```typescript
import { Hono } from 'hono'
import type { HonoEnv } from '@worker'

const app = new Hono<HonoEnv>()

// GET endpoint
app.get('/', async (c) => {
    const prisma: PrismaClient = c.get('prisma')
    const session: Session = c.get('session')
    const logger = c.get('logger')
    
    try {
        // Your business logic here
        const data = await prisma.someModel.findMany()
        
        return c.json({ success: true, data })
    } catch (error) {
        logger.error('Error in endpoint:', error)
        return c.json({ error: 'Internal Server Error' }, 500)
    }
})

// POST endpoint with parameters
app.post('/:uuid', async (c) => {
    const uuid = c.req.param('uuid')
    const body = await c.get('json')
    const prisma: PrismaClient = c.get('prisma')
    
    // Your logic here
    return c.json({ success: true, uuid })
})

export default app
```

### Route Registration
After creating an API endpoint, register it in `_worker.ts`:

```typescript
import newEndpoint from './api/new-endpoint'
app.route('/api/new-endpoint', newEndpoint)
```

### Error Handling
Consistent error handling across all endpoints:

```typescript
try {
    // Your logic
    return c.json({ success: true, data })
} catch (error) {
    const logger = c.get('logger')
    logger.error('Operation failed:', error)
    return c.json({ error: 'Internal Server Error' }, 500)
}
```

## Best Practices

- Use `async/await` instead of `.then()` and `.catch()`
- Follow the established project structure
- Validate all inputs on backend
- Never commit secrets or sensitive information
- **Monitor Core Web Vitals** and page performance metrics
