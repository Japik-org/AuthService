package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.livecycle.AShortLiveCycleImpl;
import com.pro100kryto.server.livecycle.controller.ILiveCycleImplId;
import com.pro100kryto.server.livecycle.controller.LiveCycleController;
import com.pro100kryto.server.livecycle.controller.LiveCycleImplId;
import com.pro100kryto.server.module.IModuleConnectionSafe;
import com.pro100kryto.server.modules.crypt.connection.ICryptModuleConnection;
import com.pro100kryto.server.modules.usermodel.connection.IUserModelModuleConnection;
import com.pro100kryto.server.service.AService;
import com.pro100kryto.server.service.BaseServiceSettings;
import com.pro100kryto.server.service.ServiceConnectionParams;
import com.pro100kryto.server.service.ServiceParams;
import com.pro100kryto.server.services.auth.connection.IAuthServiceConnection;
import lombok.Getter;
import lombok.Setter;

import java.rmi.RemoteException;

public final class AuthService extends AService<IAuthServiceConnection> {
    @Getter
    private AuthMap authMap;
    private IModuleConnectionSafe<IUserModelModuleConnection> userModelModuleConnectionSafe;
    private IModuleConnectionSafe<ICryptModuleConnection> signCryptModuleConnectionSafe;

    public AuthService(ServiceParams serviceParams) {
        super(serviceParams);
    }

    public IUserModelModuleConnection getUserModel() throws RemoteException {
        return userModelModuleConnectionSafe.getModuleConnection();
    }

    @Override
    protected void initLiveCycleController(LiveCycleController liveCycleController) {
        super.initLiveCycleController(liveCycleController);

        liveCycleController.getInitImplQueue().put(new LiveCycleImplId(
                "init settings", LiveCycleController.PRIORITY_HIGHEST
        ), ()-> {
            settings.put(BaseServiceSettings.KEY_CONNECTION_MULTIPLE_ENABLED, false);
            settings.put(BaseServiceSettings.KEY_CONNECTION_CREATE_AFTER_INIT_ENABLED, true);
        });

        liveCycleController.putImplAll(new AuthServiceLiveCycleImpl());
    }

    @Override
    public IAuthServiceConnection createServiceConnection(ServiceConnectionParams params) {
        return new AuthServiceConnection(this, params,
                settings.getBooleanOrDefault("auth-multiconnections-enabled", false),
                settings.getBooleanOrDefault("auth-reconnect-enabled", true)
        );
    }

    private final class AuthServiceLiveCycleImpl extends AShortLiveCycleImpl implements ILiveCycleImplId {
        @Getter
        private final String name = "AuthServiceLiveCycleImpl";
        @Getter @Setter
        private int priority = LiveCycleController.PRIORITY_NORMAL;

        @Override
        public void init() throws Throwable {
            {
                final String signCryptModuleName = settings.getOrDefault("module-signCrypt", "signCrypt");
                initModuleOrWarn(signCryptModuleName);
                signCryptModuleConnectionSafe = setupModuleConnectionSafe(signCryptModuleName);
            }

            {
                authMap = new AuthMap(
                        signCryptModuleConnectionSafe,
                        settings.getIntOrDefault("auth-capacity", Integer.MAX_VALUE)
                );
            }

            {
                final String userModelModuleName = settings.getOrDefault("module-userModel", "userModel");
                initModuleOrWarn(userModelModuleName);
                userModelModuleConnectionSafe = setupModuleConnectionSafe(userModelModuleName);
            }
        }

        @Override
        public void start() throws Throwable {
            startModuleOrThrow(userModelModuleConnectionSafe.getModuleName());
            startModuleOrThrow(signCryptModuleConnectionSafe.getModuleName());
        }

        @Override
        public void stopForce() {
            closeModuleConnection(userModelModuleConnectionSafe);
            closeModuleConnection(signCryptModuleConnectionSafe);
            authMap.closeAllAndClear();
        }

        @Override
        public void destroy() {
            userModelModuleConnectionSafe = closeModuleConnection(userModelModuleConnectionSafe);
            signCryptModuleConnectionSafe = closeModuleConnection(signCryptModuleConnectionSafe);

            if (authMap != null) {
                authMap.closeAllAndClear();
                authMap = null;
            }
        }
    }
}
