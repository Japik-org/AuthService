package com.pro100kryto.server.services.auth;

import com.pro100kryto.server.module.IModuleConnectionSafe;
import com.pro100kryto.server.modules.crypt.connection.ICryptModuleConnection;
import com.pro100kryto.server.modules.usermodel.connection.IUserModel;
import com.pro100kryto.server.services.auth.connection.IUserConn;
import org.eclipse.collections.impl.map.mutable.primitive.IntObjectHashMap;
import org.eclipse.collections.impl.map.mutable.primitive.LongObjectHashMap;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.rmi.RemoteException;
import java.util.Collections;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public final class AuthMap implements IUserConnCallback {
    private final IModuleConnectionSafe<ICryptModuleConnection> signCryptModule;

    private final IntObjectHashMap<IUserConn> connIdUserConnMap;
    private final LongObjectHashMap< IntObjectHashMap<IUserConn> > userIdUserConnMap;

    private final int capacity;
    private final AtomicInteger counter;
    private final AtomicInteger connIdCounter = new AtomicInteger(1);

    private final ReentrantLock lock = new ReentrantLock();

    public AuthMap(IModuleConnectionSafe<ICryptModuleConnection> signCryptModule, int capacity) {
        this.signCryptModule = signCryptModule;
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

    public IUserConn createConnAndPut(IUserModel userModel) throws RemoteException {
        if (counter.get() == capacity){
            throw new IllegalStateException();
        }

        lock.lock();
        try {

            final int connId = connIdCounter.getAndIncrement();

            final IUserConn userConn = new UserConnFromUserModel(
                    this,
                    connId,
                    userModel,
                    getSignCrypt().combine(
                            ByteBuffer.allocate(Integer.SIZE/8)
                                    .order(ByteOrder.LITTLE_ENDIAN)
                                    .putInt(connId)
                                    .array(),
                            ByteBuffer.allocate(Long.SIZE/8)
                                    .order(ByteOrder.LITTLE_ENDIAN)
                                    .putLong(userModel.getId())
                                    .array()
                    )
            );

            connIdUserConnMap.put(connId, userConn);
            if (userIdUserConnMap.containsKey(userModel.getId())){
                userIdUserConnMap.get(userConn.getUserId()).put(userConn.getConnId(), userConn);
            } else {
                userIdUserConnMap.put(userConn.getUserId(), new IntObjectHashMap<IUserConn>(1){{
                    put(connId, userConn);
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

            } catch (RemoteException ignored) {

            } finally {
                lock.unlock();
            }
        }
    }

    @Override
    public void onUserConnClose(IUserConn userConn) throws RemoteException {
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

    @Override
    public ICryptModuleConnection getSignCrypt() throws RemoteException {
        return signCryptModule.getModuleConnection();
    }
}
