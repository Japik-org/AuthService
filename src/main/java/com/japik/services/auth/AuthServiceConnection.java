package com.japik.services.auth;

import com.japik.service.AServiceConnection;
import com.japik.service.ServiceConnectionParams;
import com.japik.services.auth.connection.*;
import com.japik.services.usersdatabase.shared.IUser;
import com.japik.utils.databasequery.req.DatabaseQueryException;
import com.japik.utils.databasequery.req.ObjectNotFoundException;
import com.japik.utils.databasequery.req.OnResolveQueryException;
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
    public long createUser(IAuthInsertUser userInfo) throws RemoteException, AuthorizationException {
        try {
            final IUser user = service.getUsersDatabase().getUsersCollection().prepareInsert(new InsertUserWrapper(userInfo));
            user.queryInsert();
            return user.reqId().resolveAndGetValue();

        } catch (com.japik.services.usersdatabase.shared.UserAlreadyExistsException userAlreadyExistsException) {
            final long id = userAlreadyExistsException.getId();
            throw new AuthUserAlreadyExistsException(id);

        } catch (RemoteException passException){
            throw passException;

        } catch (Throwable throwable) {
            throw new AuthInternalErrorException(throwable);
        }
    }

    @Override
    public IUserConn authorizeByUserId(long userId, byte[] pass) throws RemoteException, AuthorizationException {
        try {
            final IUser user = service.getUsersDatabase().getUsersCollection().selectUserById(userId);
            checkUserBeforeAuthorize(userId, user, pass);
            return service.getAuthMap().createConnAndPut(
                    userId,
                    user.reqUsername().resolveAndGetValue()
            );

        } catch (ObjectNotFoundException userNotFoundException){
            throw new AuthUserNotFoundByIdException(userId);

        } catch (RemoteException | AuthorizationException passException){
            throw passException;

        } catch (Throwable throwable){
            throw new AuthInternalErrorException(throwable);
        }
    }

    @Override
    public IUserConn authorizeByUsername(String username, byte[] pass) throws RemoteException, AuthorizationException {
        try {
            final IUser user = service.getUsersDatabase().getUsersCollection().selectUserByUsername(username);
            final long userId = user.reqId().resolveAndGetValue();
            checkUserBeforeAuthorize(userId, user, pass);
            return service.getAuthMap().createConnAndPut(
                    userId,
                    username
            );

        } catch (ObjectNotFoundException userNotFoundException){
            throw new AuthUserNotFoundByUsernameException(username);

        } catch (RemoteException | AuthorizationException passException){
            throw passException;

        } catch (Throwable throwable){
            throw new AuthInternalErrorException(throwable);
        }
    }

    @Override
    public IUserConn authorizeByEmail(String email, byte[] pass) throws RemoteException, AuthorizationException {
        try {
            final IUser user = service.getUsersDatabase().getUsersCollection().selectUserByUsername(email);
            final long userId = user.reqId().resolveAndGetValue();
            checkUserBeforeAuthorize(userId, user, pass);
            return service.getAuthMap().createConnAndPut(
                    userId,
                    user.reqUsername().resolveAndGetValue()
            );

        } catch (ObjectNotFoundException userNotFoundException){
            throw new AuthUserNotFoundByEmailException(email);

        } catch (RemoteException | AuthorizationException passException){
            throw passException;

        } catch (Throwable throwable){
            throw new AuthInternalErrorException(throwable);
        }
    }

    public void checkUserBeforeAuthorize(long userId, IUser user, byte[] pass) throws RemoteException,
            AuthWrongUserPassException, AuthUserAlreadyAuthorizedException, ObjectNotFoundException {

        try {
            final boolean passCheck = user.reqVerifyPassword(pass).resolveAndGetValue();

            if (!passCheck) throw new AuthWrongUserPassException(userId);

            if (!multiconnEnabled && service.getAuthMap().containsByUserId(userId)) {
                if (allowReconnect) {
                    dismissAuthorizationsByUserId(userId);
                } else {
                    try {
                        throw new AuthUserAlreadyAuthorizedException(
                                service.getAuthMap().getByUserId(userId).next()
                        );
                    } catch (NoSuchElementException ignored) {
                    }
                }
            }

        } catch (OnResolveQueryException | DatabaseQueryException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public IUserConn getUserConnByConnId(int connId) throws AuthUserConnNotFoundException {
        final IUserConn userConn = service.getAuthMap().getByConnId(connId);
        if (userConn == null){
            throw new AuthUserConnNotFoundException(connId);
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
    public boolean isAuthorizedByUsername(String username) throws RemoteException, AuthInternalErrorException {
        try {
            return isAuthorizedByUserId(
                    service.getUsersDatabase().getUsersCollection()
                            .selectUserByUsername(username)
                            .reqId()
                            .resolveAndGetValue());

        } catch (ObjectNotFoundException e) {
            return false;

        } catch (DatabaseQueryException | OnResolveQueryException e) {
            throw new AuthInternalErrorException(e);
        }
    }

    @Override
    public void dismissAuthorizationByConnId(int connId) {
        final UserConn userConn = service.getAuthMap().getByConnId(connId);
        if (userConn == null || userConn.isClosed()) return;
        userConn.close();
    }

    @Override
    public void dismissAuthorizationsByUserId(long userId) {
        do {
            final Iterator<UserConn> userConns = service.getAuthMap().getByUserId(userId);

            if (userConns.hasNext()) {
                final UserConn userConn = userConns.next();
                if (userConn.isClosed()) continue;
                userConn.close();

            } else {
                break;
            }
        } while (true);
    }

}
