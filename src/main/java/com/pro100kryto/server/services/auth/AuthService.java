package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.livecycle.AShortLiveCycleImpl;
import com.pro100kryto.server.livecycle.ILiveCycleImpl;
import com.pro100kryto.server.service.AService;
import com.pro100kryto.server.service.ServiceParams;
import com.pro100kryto.server.services.auth.connection.IAuthServiceConnection;
import org.jetbrains.annotations.NotNull;

public final class AuthService extends AService<IAuthServiceConnection> {
    public AuthService(ServiceParams serviceParams) {
        super(serviceParams);
    }

    @Override
    public IAuthServiceConnection createServiceConnection() {
        return new AuthServiceConnection(this, logger);
    }

    @Override
    protected @NotNull ILiveCycleImpl getDefaultLiveCycleImpl() {
        return new AuthLiveCycleImpl();
    }

    private final class AuthLiveCycleImpl extends AShortLiveCycleImpl{

        @Override
        public void init() throws Throwable {

        }

        @Override
        public void start() throws Throwable {

        }

        @Override
        public void stopForce() {

        }

        @Override
        public void destroy() {

        }
    }
}
