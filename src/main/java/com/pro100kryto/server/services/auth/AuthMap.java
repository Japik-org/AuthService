package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.modules.usermodel.connection.IUserModelData;
import com.pro100kryto.server.services.auth.connection.IUserConn;
import com.pro100kryto.server.services.auth.connection.UserAlreadyAuthorizedException;
import lombok.Getter;
import lombok.Setter;
import org.eclipse.collections.impl.map.mutable.primitive.IntObjectHashMap;
import org.eclipse.collections.impl.map.mutable.primitive.LongObjectHashMap;

import java.util.Collections;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public final class AuthMap implements IUserConnCallback {
    private final IntObjectHashMap<IUserConn> connIdUserConnMap;
    private final LongObjectHashMap< IntObjectHashMap<IUserConn> > userIdUserConnMap;

    private final int capacity;
    private final AtomicInteger counter;
    private final AtomicInteger connIdCounter = new AtomicInteger(1);

    private final ReentrantLock lock = new ReentrantLock();

    @Getter @Setter
    private boolean allowMulticonn = false;

    public AuthMap(int capacity) {
        this.capacity = capacity;
        connIdUserConnMap = new IntObjectHashMap<>(capacity);
        userIdUserConnMap = new LongObjectHashMap<>(capacity);
        counter = new AtomicInteger(0);
    }

    public boolean containsByConnId(int connId){
        lock.lock();
        try {
            return connIdUserConnMap.containsKey(connId);
        } finally {
            lock.unlock();
        }
    }

    public boolean containsByUserId(long userId){
        lock.lock();
        try {
            return userIdUserConnMap.containsKey(userId);
        } finally {
            lock.unlock();
        }
    }

    public IUserConn getByConnId(int connId){
        lock.lock();
        try {
            return connIdUserConnMap.get(connId);
        } finally {
            lock.unlock();
        }
    }

    public Iterator<IUserConn> getByUserId(long userId){
        lock.lock();
        try {
            return userIdUserConnMap.get(userId).values().iterator();

        } catch (Throwable throwable){
            return Collections.emptyIterator();

        } finally {
            lock.unlock();
        }
    }

    public IUserConn createConnAndPut(IUserModelData userModelData) throws UserAlreadyAuthorizedException {
        if (counter.get() == capacity){
            throw new IllegalStateException();
        }

        lock.lock();
        try {

            if (!allowMulticonn && userIdUserConnMap.containsKey(userModelData.getUserId())) {
                throw new UserAlreadyAuthorizedException(userIdUserConnMap.get(userModelData.getUserId()).get(0));
            }

            final IUserConn userConn = new UserConnFromUserModelData(
                    connIdCounter.getAndIncrement(),
                    userModelData,
                    this
            );

            connIdUserConnMap.put(userConn.getConnId(), userConn);
            if (userIdUserConnMap.containsKey(userModelData.getUserId())){
                userIdUserConnMap.get(userConn.getUserId()).put(userConn.getConnId(), userConn);
            } else {
                userIdUserConnMap.put(userConn.getUserId(), new IntObjectHashMap<IUserConn>(1){{
                    put(userConn.getConnId(), userConn);
                }});
            }
            counter.incrementAndGet();

            return userConn;

        } finally {
            lock.unlock();
        }
    }

    public void closeAllAndClear() {
        while (!connIdUserConnMap.isEmpty()){
            lock.lock();
            try {
                connIdUserConnMap.values().iterator().next().close();
            } finally {
                lock.unlock();
            }
        }
    }

    @Override
    public void onUserConnClose(IUserConn userConn) {
        lock.lock();
        try {
            connIdUserConnMap.remove(userConn.getConnId());
            userIdUserConnMap.get(userConn.getUserId()).remove(userConn.getConnId());
            if (userIdUserConnMap.get(userConn.getUserId()).isEmpty()){
                userIdUserConnMap.remove(userConn.getUserId());
            }
            counter.decrementAndGet();
        } finally {
            lock.unlock();
        }
    }
}
