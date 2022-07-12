package com.japik.services.auth;

import com.japik.modules.crypt.connection.ICryptModuleConnection;

import java.rmi.RemoteException;

public interface IUserConnCallback {
    void onUserConnClose(UserConn conn);
    ICryptModuleConnection getSignCrypt() throws RemoteException;
}
