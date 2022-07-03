package com.japik.services.auth;

import com.japik.modules.crypt.connection.ICryptModuleConnection;
import com.japik.services.auth.connection.IUserConn;

import java.rmi.RemoteException;

public interface IUserConnCallback {
    void onUserConnClose(IUserConn conn) throws RemoteException;
    ICryptModuleConnection getSignCrypt() throws RemoteException;
}
