package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.modules.crypt.connection.ICryptModuleConnection;
import com.pro100kryto.server.services.auth.connection.IUserConn;

import java.rmi.RemoteException;

public interface IUserConnCallback {
    void onUserConnClose(IUserConn conn) throws RemoteException;
    ICryptModuleConnection getSignCrypt() throws RemoteException;
}
