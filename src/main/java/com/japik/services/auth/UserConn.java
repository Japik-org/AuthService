package com.japik.services.auth;

import com.japik.services.auth.connection.IUserConn;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.rmi.RemoteException;

@RequiredArgsConstructor
@Getter
public final class UserConn implements IUserConn {
    private final IUserConnCallback callback;
    private final int connId;
    private final byte[] secret;
    private boolean isClosed = false;

    private final Object userId;
    private final String username;

    @Override
    public boolean checkSign(byte[] sign, byte[] src) throws RemoteException {
        return callback.getSignCrypt().check(sign, src, secret);
    }

    @Override
    public synchronized void close() {
        if (isClosed) return;
        isClosed = true;
        callback.onUserConnClose(this);
    }
}
