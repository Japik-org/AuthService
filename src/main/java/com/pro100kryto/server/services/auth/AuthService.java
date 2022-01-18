package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.livecycle.AShortLiveCycleImpl;
import com.pro100kryto.server.livecycle.ILiveCycleImpl;
import com.pro100kryto.server.module.IModuleConnectionSafe;
import com.pro100kryto.server.modules.usermodel.connection.IUserModelModuleConnection;
import com.pro100kryto.server.service.AService;
import com.pro100kryto.server.service.BaseServiceSettings;
import com.pro100kryto.server.service.ServiceConnectionParams;
import com.pro100kryto.server.service.ServiceParams;
import com.pro100kryto.server.services.auth.connection.IAuthServiceConnection;
import lombok.Getter;
import org.jetbrains.annotations.NotNull;

public final class AuthService extends AService<IAuthServiceConnection> {
    @Getter
    private AuthMap authMap;
    private IModuleConnectionSafe<IUserModelModuleConnection> userModelModuleConnectionSafe;

    public AuthService(ServiceParams serviceParams) {
        super(serviceParams);
    }

    public IUserModelModuleConnection getUserModel() throws Throwable {
        return userModelModuleConnectionSafe.getModuleConnection();
    }

    @Override
    protected void setupSettingsBeforeInit() throws Throwable {
        settings.put(BaseServiceSettings.KEY_CONNECTION_CREATE_AFTER_INIT_ENABLED, true);

        super.setupSettingsBeforeInit();
    }

    @Override
    public IAuthServiceConnection createServiceConnection(ServiceConnectionParams params) {
        return new AuthServiceConnection(this, params);
    }

    @Override
    protected @NotNull ILiveCycleImpl createDefaultLiveCycleImpl() {
        return new AuthServiceLiveCycleImpl();
    }

    private final class AuthServiceLiveCycleImpl extends AShortLiveCycleImpl {

        @Override
        public void init() throws Throwable {
            authMap = new AuthMap(settings.getIntOrDefault("auth-capacity", Integer.MAX_VALUE));
            userModelModuleConnectionSafe = setupModuleConnectionSafe("userModel");
        }

        @Override
        public void start() throws Throwable {

        }

        @Override
        public void stopForce() {
            authMap.closeAllAndClear();
        }

        @Override
        public void destroy() {
            userModelModuleConnectionSafe.close();
            userModelModuleConnectionSafe = null;
            authMap = null;
        }
    }
}
