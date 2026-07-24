import fastifySwagger from "@fastify/swagger";
import fastifySwaggerUi from "@fastify/swagger-ui";
import { adminRoutes } from "./modules/admin/admin.route.js";

import Fastify from "fastify";
import { env } from "./config/env.js";
import { authRoutes } from "./modules/auth/auth.route.js";

// Instantiate Fastify with built-in Pino logger
const server = Fastify({
    logger: {
        level: env.NODE_ENV === "test" ? "silent" : "info",
    },
});

// Register Swagger (OpenAPI) documentation BEFORE registering your routes
server.register(fastifySwagger, {
    openapi: {
        info: {
            title: "Swaraksha Auth API",
            description: "High-performance Auth API with RBAC, MFA, and Rate Limiting",
            version: "1.0.0",
        },
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT",
                },
            },
        },
    },
});

server.register(fastifySwaggerUi, {
    routePrefix: "/docs",
});


// Register our authentication routes
server.register(authRoutes);
server.register(adminRoutes, { prefix: "/admin" });

// Global Error Handler for uncaught exceptions or custom domain errors
server.setErrorHandler((error: any, request, reply) => {
    server.log.error(error);

    const statusCode = error.statusCode ?? 500;
    const message =
        env.NODE_ENV === "production" && statusCode === 500
            ? "Internal Server Error"
            : error.message;

    reply.status(statusCode).send({
        error: error.name ?? "Error",
        message,
    });
});

// Start the server
const start = async () => {
    try {
        const address = await server.listen({ port: env.PORT, host: "0.0.0.0" });
        console.log(`🚀 Production Auth API running at: ${address}`);
    } catch (err) {
        server.log.error(err);
        process.exit(1);
    }
};

// Only start listening if this file is run directly (not imported during testing)
if (process.env.NODE_ENV !== "test") {
    start();
}

export { server };
