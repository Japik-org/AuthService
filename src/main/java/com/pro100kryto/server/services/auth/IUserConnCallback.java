package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.services.auth.connection.IUserConn;

public interface IUserConnCallback {
    void onUserConnClose(IUserConn conn);
}
