package com.japik.services.auth;

import com.japik.modules.crypt.connection.ICryptModuleConnection;
import org.eclipse.collections.impl.map.mutable.primitive.IntObjectHashMap;

import java.rmi.RemoteException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public final class AuthMap implements IUserConnCallback {
    private final AuthService service;
    private final IntObjectHashMap<UserConn> connIdUserConnMap;
    private final HashMap<Object, IntObjectHashMap<UserConn> > userIdUserConnMap;

    private final int capacity;
    private final AtomicInteger counter;
    private final AtomicInteger connIdCounter = new AtomicInteger(1);

    private final ReentrantLock lock = new ReentrantLock();

    public AuthMap(AuthService service, int capacity) {
        this.service = service;
        this.capacity = capacity;
        connIdUserConnMap = new IntObjectHashMap<>(capacity);

        // fix memory allocation
        connIdUserConnMap.put(0, null);
        connIdUserConnMap.remove(0);

        userIdUserConnMap = new HashMap<>(capacity);

        // fix memory allocation
        userIdUserConnMap.put(this, null);
        userIdUserConnMap.remove(this);

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

    public boolean containsByUserId(Object userId){
        lock.lock();
        try {
            return userIdUserConnMap.containsKey(userId);
        } finally {
            lock.unlock();
        }
    }

    public UserConn getByConnId(int connId){
        lock.lock();
        try {
            return connIdUserConnMap.get(connId);
        } finally {
            lock.unlock();
        }
    }

    public Iterator<UserConn> getByUserId(Object userId){
        lock.lock();
        try {
            return userIdUserConnMap.get(userId).values().iterator();

        } catch (Throwable throwable){
            return Collections.emptyIterator();

        } finally {
            lock.unlock();
        }
    }

    public UserConn createConnAndPut(Object userId, String username) throws RemoteException {
        if (counter.get() == capacity){
            throw new IllegalStateException();
        }

        lock.lock();
        try {

            final int connId = connIdCounter.getAndIncrement();

            final UserConn userConn = new UserConn(
                    this,
                    connId,
                    service.getSignCryptModuleConnectionSafe().getModuleConnection().randomSalt(8),
                    userId,
                    username
            );

            connIdUserConnMap.put(connId, userConn);
            if (userIdUserConnMap.containsKey(userId)){
                userIdUserConnMap.get(userConn.getUserId()).put(userConn.getConnId(), userConn);
            } else {
                final IntObjectHashMap<UserConn> map1 = new IntObjectHashMap<UserConn>(1);
                map1.put(connId, userConn);
                final Object userId2 = userConn.getUserId();
                userIdUserConnMap.put(userId2, map1);
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
    public void onUserConnClose(UserConn userConn) {
        lock.lock();
        try {
            connIdUserConnMap.remove(userConn.getConnId());
            userIdUserConnMap.get(userConn.getUserId()).remove(userConn.getConnId());
            if (userIdUserConnMap.get(userConn.getUserId()).isEmpty()) {
                userIdUserConnMap.remove(userConn.getUserId());
            }
            counter.decrementAndGet();

        } finally {
            lock.unlock();
        }
    }

    @Override
    public ICryptModuleConnection getSignCrypt() throws RemoteException {
        return service.getSignCryptModuleConnectionSafe().getModuleConnection();
    }
}
