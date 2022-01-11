package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.logger.ILogger;
import com.pro100kryto.server.service.AServiceConnection;
import com.pro100kryto.server.services.auth.connection.IAuthServiceConnection;
import org.jetbrains.annotations.NotNull;

public class AuthServiceConnection extends AServiceConnection<AuthService, IAuthServiceConnection> implements IAuthServiceConnection {
    public AuthServiceConnection(@NotNull AuthService service, ILogger logger) {
        super(service, logger);
    }


}
