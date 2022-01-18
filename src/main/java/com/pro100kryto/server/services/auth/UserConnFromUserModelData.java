package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.modules.usermodel.connection.IUserModelData;
import com.pro100kryto.server.services.auth.connection.IUserConn;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public final class UserConnFromUserModelData implements IUserConn {
    private final int connId;
    private final IUserModelData userData;
    private final IUserConnCallback callback;

    @Override
    public long getUserId() {
        return userData.getUserId();
    }

    @Override
    public String getNickname() {
        return userData.getNickname();
    }

    @Override
    public boolean checkSign(byte[] sign, byte[] src) {
        return userData.checkSign(sign, src);
    }

    @Override
    public boolean checkPass(byte[] pass) {
        return userData.checkPass(pass);
    }

    @Override
    public void close() {
        userData.close();
    }

    @Override
    public boolean isClosed() {
        return userData.isClosed();
    }
}
