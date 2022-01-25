package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.modules.usermodel.connection.IUserModelData;
import com.pro100kryto.server.service.AServiceConnection;
import com.pro100kryto.server.service.ServiceConnectionParams;
import com.pro100kryto.server.services.auth.connection.*;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.rmi.RemoteException;
import java.util.Iterator;
import java.util.NoSuchElementException;

public final class AuthServiceConnection extends AServiceConnection<AuthService, IAuthServiceConnection>
        implements IAuthServiceConnection {

    @Getter @Setter
    private boolean multiconnEnabled;
    @Getter @Setter
    private boolean allowReconnect;

    public AuthServiceConnection(@NotNull AuthService service, ServiceConnectionParams params,
                                 boolean multiconnEnabled, boolean allowReconnect) {
        super(service, params);
        this.multiconnEnabled = multiconnEnabled;
        this.allowReconnect = allowReconnect;
    }

    @Override
    public IUserConn authorizeByUserId(long userId, byte[] pass) throws AuthorizationException {
        if (!service.getLiveCycle().getStatus().isStarted()){
            throw new AuthorizationDisabledException();
        }

        try {
            final IUserModelData userData = service.getUserModel().getUserByUserId(userId);
            checkUserBeforeAuthorize(userData, pass);
            return service.getAuthMap().createConnAndPut(userData);

        } catch (com.pro100kryto.server.modules.usermodel.connection.UserNotFoundException userNotFoundException){
            throw new UserNotFoundException(
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
            checkUserBeforeAuthorize(userData, pass);
            return service.getAuthMap().createConnAndPut(userData);

        } catch (com.pro100kryto.server.modules.usermodel.connection.UserNotFoundException userNotFoundException) {
            throw new UserNotFoundException(
                    userNotFoundException.getKey(), userNotFoundException.getVal()
            );

        } catch (AuthorizationException authorizationException){
            throw authorizationException;

        } catch (Throwable throwable){
            throw new AuthorizationInternalErrorException(throwable);
        }
    }

    public void checkUserBeforeAuthorize(IUserModelData userData, byte[] pass)
            throws WrongUserPassException, UserAlreadyAuthorizedException, RemoteException {

        if (!userData.checkPass(pass)) {
            throw new WrongUserPassException(userData.getUserId());
        }

        if (!multiconnEnabled && service.getAuthMap().containsByUserId(userData.getUserId())){
            if (allowReconnect){
                dismissAllAuthorizationsByUserId(userData.getUserId());
            } else {
                try {
                    throw new UserAlreadyAuthorizedException(service.getAuthMap().getByUserId(userData.getUserId()).next());
                } catch (NoSuchElementException ignored) {
                }
            }
        }
    }

    @Override
    public IUserConn getUserConnByConnId(int connId) throws UserConnNotFound {
        final IUserConn userConn = service.getAuthMap().getByConnId(connId);
        if (userConn == null){
            throw new UserConnNotFound(connId);
        }
        return userConn;
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
    public boolean dismissAuthorizationByConnId(int connId) throws RemoteException {
        final IUserConn userConn = service.getAuthMap().getByConnId(connId);
        if (userConn == null) return false;
        if (userConn.isClosed()) return true;
        userConn.close();
        return true;
    }

    @Override
    public boolean dismissAllAuthorizationsByUserId(long userId) throws RemoteException {
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
