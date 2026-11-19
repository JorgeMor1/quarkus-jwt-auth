package io.github.JorgeMor1.resource;

import io.github.JorgeMor1.auth.KeyRotationManager;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.CacheControl;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

@Path("/.well-known/jwks.json")
public class JwksResource {
    private static final Logger LOG = Logger.getLogger(JwksResource.class);

    @Inject
    KeyRotationManager keyRotationManager;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJwks() {
        try {
            CacheControl cacheControl = new CacheControl();
            cacheControl.setMaxAge(3600);
            cacheControl.setPrivate(false);

            return Response.ok(keyRotationManager.getPublicJwkSet().toJSONObject())
                    .cacheControl(cacheControl)
                    .build();

        } catch (Exception e) {
            LOG.error("Falha crítica ao gerar ou serializar o JWKS público", e);

            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\": \"Erro ao carregar JWKS\"}")
                    .build();
        }
    }
}
