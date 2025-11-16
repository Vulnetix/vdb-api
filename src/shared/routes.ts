/**
 * Centralized route configuration for the VDB application
 * This file contains all public route paths and authentication rules
 * to maintain consistency across the frontend and backend
 */

/**
 * Blog-specific route paths - removed for VDB focus
 */
export const blogRoutePaths: string[] = []

/**
 * Unauthenticated routes configuration for middleware
 * Routes that do not require authentication challenges
 * Used by both frontend router guards and backend middleware
 */
export const unauthenticatedRoutes = {
    /**
     * Static routes that never require authentication
     */
    static: [
        "/v1/spec",
                "/v1/oas",
        "/v1/spec/ui",
        "/v1/info",
    ],
    /**
     * Route prefixes that never require authentication
     * Any route starting with these prefixes will bypass auth
     */
    prefixes: [
        '/auth/', // OpenAPI specification and Swagger UI
    ],
}
