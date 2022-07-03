package com.japik.services.auth;

import com.japik.modules.usermodel.connection.IUserModel;
import com.japik.services.auth.connection.IUserConn;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.rmi.RemoteException;

@RequiredArgsConstructor
public final class UserConnFromUserModel implements IUserConn {
    private final IUserConnCallback callback;
    @Getter
    private final int connId;
    @Getter
    private final IUserModel userData;

    private final byte[] secret;

    @Override
    public long getUserId() throws RemoteException {
        return userData.getId();
    }

    @Override
    public String getNickname() throws RemoteException {
        return userData.getUsername();
    }

    @Override
    public boolean checkSign(byte[] sign, byte[] src) throws RemoteException {
        return callback.getSignCrypt().check(sign, src, secret);
    }

    @Override
    public boolean checkPass(byte[] pass) throws RemoteException {
        return userData.checkPass(pass);
    }

    @Override
    public void close() throws RemoteException {
        userData.close();
    }

    @Override
    public boolean isClosed() throws RemoteException {
        return userData.isClosed();
    }
}
