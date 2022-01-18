package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.modules.usermodel.connection.IUserModelData;
import com.pro100kryto.server.modules.usermodel.connection.UserNotFoundException;
import com.pro100kryto.server.service.AServiceConnection;
import com.pro100kryto.server.service.ServiceConnectionParams;
import com.pro100kryto.server.services.auth.connection.*;
import org.jetbrains.annotations.NotNull;

import java.util.Iterator;

public final class AuthServiceConnection extends AServiceConnection<AuthService, IAuthServiceConnection>
        implements IAuthServiceConnection {

    public AuthServiceConnection(@NotNull AuthService service, ServiceConnectionParams params) {
        super(service, params);
    }

    @Override
    public IUserConn authorizeByUserId(long userId, byte[] pass) throws AuthorizationException {
        if (!service.getLiveCycle().getStatus().isStarted()){
            throw new AuthorizationDisabledException();
        }

        try {
            final IUserModelData userData = service.getUserModel().getUserByUserId(userId);
            if (!userData.checkPass(pass)) {
                throw new WrongUserPassException(userData.getUserId());
            }

            return service.getAuthMap().createConnAndPut(userData);

        } catch (UserNotFoundException userNotFoundException){
            throw new com.pro100kryto.server.services.auth.connection.UserNotFoundException(
                    userNotFoundException.getKey(),
                    userNotFoundException.getVal()
            );

        } catch (AuthorizationException authorizationException){
            throw authorizationException;

        } catch (Throwable throwable){
            throw new AuthorizationInternalErrorException(throwable);
        }
    }

    @Override
    public IUserConn authorizeByKeyVal(Object key, Object val, byte[] pass) throws AuthorizationException {
        if (!service.getLiveCycle().getStatus().isStarted()){
            throw new AuthorizationDisabledException();
        }

        try {
            final IUserModelData userData = service.getUserModel().getUserByKeyVal(key, val);

            return service.getAuthMap().createConnAndPut(userData);


        } catch (AuthorizationException authorizationException){
            throw authorizationException;

        } catch (Throwable throwable){
            throw new AuthorizationInternalErrorException(throwable);
        }
    }

    @Override
    public IUserConn getUserConnByConnId(int connId) throws UserConnNotFound {
        return service.getAuthMap().getByConnId(connId);
    }

    @Override
    public boolean isAuthorizedByConnId(int connId) {
        return service.getAuthMap().containsByConnId(connId);
    }

    @Override
    public boolean isAuthorizedByUserId(long userId) {
        return service.getAuthMap().containsByUserId(userId);
    }


    @Override
    public boolean dismissAuthorizationByConnId(int connId) {
        final IUserConn userConn = service.getAuthMap().getByConnId(connId);
        if (userConn == null) return false;
        if (userConn.isClosed()) return true;
        userConn.close();
        return true;
    }

    @Override
    public boolean dismissAllAuthorizationsByUserId(long userId) {
        final Iterator<IUserConn> userConns = service.getAuthMap().getByUserId(userId);

        if (!userConns.hasNext()) return false;

        while (userConns.hasNext()){
            final IUserConn userConn = userConns.next();
            if (userConn.isClosed()) continue;
            userConn.close();
        }

        return true;
    }

}
