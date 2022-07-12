package com.japik.services.auth;

import com.japik.services.auth.connection.IAuthInsertUser;
import com.japik.services.usersdatabase.shared.IUserInsert;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class InsertUserWrapper implements IUserInsert {
    private final IAuthInsertUser authInsertUser;

    @Override
    public String getUsername() {
        return authInsertUser.getUsername();
    }

    @Override
    public String getEmail() {
        return authInsertUser.getEmail();
    }

    @Override
    public byte[] getPass() {
        return authInsertUser.getPass();
    }
}
