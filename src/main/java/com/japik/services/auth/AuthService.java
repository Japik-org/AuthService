package com.japik.services.auth;

import com.japik.livecycle.AShortLiveCycleImpl;
import com.japik.livecycle.controller.ILiveCycleImplId;
import com.japik.livecycle.controller.LiveCycleController;
import com.japik.livecycle.controller.LiveCycleImplId;
import com.japik.module.IModuleConnectionSafe;
import com.japik.modules.crypt.connection.ICryptModuleConnection;
import com.japik.service.*;
import com.japik.services.auth.connection.IAuthServiceConnection;
import com.japik.services.usersdatabase.shared.IUsersDatabaseServiceConnection;
import lombok.Getter;
import lombok.Setter;

import java.rmi.RemoteException;

@Getter
public final class AuthService extends AService<IAuthServiceConnection> {
    private AuthMap authMap;
    private IServiceConnectionSafe<IUsersDatabaseServiceConnection> usersDatabaseConnectionSafe;
    private IModuleConnectionSafe<ICryptModuleConnection> signCryptModuleConnectionSafe;

    public AuthService(ServiceParams serviceParams) {
        super(serviceParams);
    }

    public IUsersDatabaseServiceConnection getUsersDatabase() throws RemoteException {
        return usersDatabaseConnectionSafe.getServiceConnection();
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

        liveCycleController.putImplAll(new AuthServiceLiveCycleImpl(this));
    }

    @Override
    public IAuthServiceConnection createServiceConnection(ServiceConnectionParams params) {
        return new AuthServiceConnection(this, params,
                settings.getBooleanOrDefault("auth-multiconnections-enabled", false),
                settings.getBooleanOrDefault("auth-reconnect-enabled", true)
        );
    }

    private final class AuthServiceLiveCycleImpl extends AShortLiveCycleImpl implements ILiveCycleImplId {
        private final AuthService service;
        @Getter
        private final String name = "AuthServiceLiveCycleImpl";
        @Getter @Setter
        private int priority = LiveCycleController.PRIORITY_NORMAL;

        private AuthServiceLiveCycleImpl(AuthService service) {
            this.service = service;
        }

        @Override
        public void init() throws Throwable {
            {
                final String signCryptModuleName = settings.getOrDefault("module-signCrypt", "signCrypt");
                initModuleOrWarn(signCryptModuleName);
                signCryptModuleConnectionSafe = setupModuleConnectionSafe(signCryptModuleName);
            }

            {
                authMap = new AuthMap(
                        service,
                        settings.getIntOrDefault("auth-capacity", 1024)
                );
            }

            {
                final String usersDatabaseServiceName = settings.getOrDefault("service-usersDatabase", "usersDatabase");
                usersDatabaseConnectionSafe = setupServiceConnectionSafe(usersDatabaseServiceName);
            }
        }

        @Override
        public void start() throws Throwable {
            startModuleOrThrow(signCryptModuleConnectionSafe.getModuleName());
        }

        @Override
        public void stopForce() {
        }

        @Override
        public void destroy() {
            authMap.closeAllAndClear();

            usersDatabaseConnectionSafe = closeServiceConnection(usersDatabaseConnectionSafe);
            signCryptModuleConnectionSafe = closeModuleConnection(signCryptModuleConnectionSafe);

            if (authMap != null) {
                authMap.closeAllAndClear();
                authMap = null;
            }
        }
    }
}
