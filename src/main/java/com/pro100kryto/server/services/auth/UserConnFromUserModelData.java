package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.modules.usermodel.connection.IUserModelData;
import com.pro100kryto.server.services.auth.connection.IUserConn;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.rmi.RemoteException;

@RequiredArgsConstructor
public final class UserConnFromUserModelData implements IUserConn {
    private final IUserConnCallback callback;
    @Getter
    private final int connId;
    @Getter
    private final IUserModelData userData;

    private final byte[] secret;

    @Override
    public long getUserId() throws RemoteException {
        return userData.getUserId();
    }

    @Override
    public String getNickname() throws RemoteException {
        return userData.getNickname();
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
