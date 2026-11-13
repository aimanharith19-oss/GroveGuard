/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.fw;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;

import org.grove.guard.App;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Talks to Shizuku (https://shizuku.rikka.app) to run the firewall's shell commands with ADB-level rights.
 * Speaks Shizuku's public binder protocol directly (from its MIT-licensed API definitions), so no library is
 * bundled. The same approach Canopy Launcher uses.
 */
public final class Shizuku {
    private Shizuku() { }

    public static final String MANAGER = "moe.shizuku.privileged.api";
    private static final String SERVICE = "moe.shizuku.server.IShizukuService";
    private static final String APPLICATION = "moe.shizuku.server.IShizukuApplication";
    private static final String PROCESS = "moe.shizuku.server.IRemoteProcess";
    private static final String EXTRA_BINDER = "moe.shizuku.privileged.api.intent.extra.BINDER";
    // transaction codes = FIRST_CALL_TRANSACTION (1) + the ids in IShizukuService.aidl
    private static final int T_NEW_PROCESS = 8, T_REQUEST_PERMISSION = 15, T_CHECK_SELF = 16, T_ATTACH = 18;
    private static final int P_GET_INPUT = 2, P_WAIT_FOR = 4;

    private static volatile IBinder binder;
    private static volatile boolean granted;
    private static volatile Runnable pending;

    public interface Listener { void onShizukuChanged(); }

    private static final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();

    public static void addListener(Listener l) { listeners.add(l); }

    public static void removeListener(Listener l) { listeners.remove(l); }

    private static void changed() {
        App.MAIN.post(new Runnable() { @Override public void run() { for (Listener l : listeners) l.onShizukuChanged(); } });
    }

    /** Receives what Shizuku sends to our app: bind info and the answer to the permission request. */
    private static final Binder CLIENT = new Binder() {
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            if (code == INTERFACE_TRANSACTION) { reply.writeString(APPLICATION); return true; }
            try {
                data.enforceInterface(APPLICATION);
                if (code == 2) { // bindApplication(Bundle)
                    Bundle b = data.readInt() != 0 ? Bundle.CREATOR.createFromParcel(data) : null;
                    if (b != null) granted = b.getBoolean("shizuku:attach-reply-permission-granted", granted);
                    changed();
                    return true;
                }
                if (code == 3) { // dispatchRequestPermissionResult(int, Bundle)
                    data.readInt();
                    Bundle b = data.readInt() != 0 ? Bundle.CREATOR.createFromParcel(data) : null;
                    granted = b != null && b.getBoolean("shizuku:request-permission-reply-allowed", false);
                    final Runnable r = pending;
                    pending = null;
                    if (granted && r != null) App.IO.execute(r);
                    changed();
                    if (granted) Firewall.onBackendReady(App.ctx());
                    return true;
                }
            } catch (Throwable ignored) { }
            return true;
        }
    };

    static void onBinder(IBinder b, String pkg) {
        if (b == null || b == binder) return;
        binder = b;
        try {
            b.linkToDeath(new IBinder.DeathRecipient() {
                @Override public void binderDied() { binder = null; granted = false; changed(); }
            }, 0);
        } catch (Throwable ignored) { }
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        try {
            Bundle args = new Bundle();
            args.putInt("shizuku:attach-api-version", 13);
            args.putString("shizuku:attach-package-name", pkg);
            data.writeInterfaceToken(SERVICE);
            data.writeStrongBinder(CLIENT);
            data.writeInt(1);
            args.writeToParcel(data, 0);
            b.transact(T_ATTACH, data, reply, 0);
            reply.readException();
        } catch (Throwable ignored) {
        } finally { data.recycle(); reply.recycle(); }
        checkGranted();
        changed();
        if (granted) Firewall.onBackendReady(App.ctx());
    }

    public static boolean installed(Context c) {
        try { c.getPackageManager().getPackageInfo(MANAGER, 0); return true; } catch (PackageManager.NameNotFoundException e) { return false; }
    }

    public static boolean running() { IBinder b = binder; return b != null && b.pingBinder(); }

    public static boolean granted() { return running() && (granted || checkGranted()); }

    private static boolean checkGranted() {
        IBinder b = binder;
        if (b == null) return false;
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(SERVICE);
            b.transact(T_CHECK_SELF, data, reply, 0);
            reply.readException();
            granted = reply.readInt() != 0;
        } catch (Throwable t) {
            granted = false;
        } finally { data.recycle(); reply.recycle(); }
        return granted;
    }

    /** Shows Shizuku's "allow Grove Guard?" prompt; runs {@code then} (in the background) once allowed. */
    public static void requestPermission(Runnable then) {
        IBinder b = binder;
        if (b == null) return;
        pending = then;
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(SERVICE);
            data.writeInt(1);
            b.transact(T_REQUEST_PERMISSION, data, reply, 0);
            reply.readException();
        } catch (Throwable ignored) {
        } finally { data.recycle(); reply.recycle(); }
    }

    /** Runs {@code sh -c script} as Shizuku's user and waits. Returns null if Shizuku can't be used. */
    static Shell.Result exec(String script) {
        IBinder b = binder;
        if (b == null || !granted()) return null;
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        IBinder proc = null;
        try {
            data.writeInterfaceToken(SERVICE);
            data.writeStringArray(new String[]{"sh", "-c", script});
            data.writeStringArray(null);
            data.writeString(null);
            b.transact(T_NEW_PROCESS, data, reply, 0);
            reply.readException();
            proc = reply.readStrongBinder();
        } catch (Throwable t) {
            return null;
        } finally { data.recycle(); reply.recycle(); }
        if (proc == null) return null;
        String out = "";
        Parcel d1 = Parcel.obtain(), r1 = Parcel.obtain();
        try { // stdout
            d1.writeInterfaceToken(PROCESS);
            proc.transact(P_GET_INPUT, d1, r1, 0);
            r1.readException();
            if (r1.readInt() != 0) {
                ParcelFileDescriptor pfd = ParcelFileDescriptor.CREATOR.createFromParcel(r1);
                try (InputStream in = new FileInputStream(pfd.getFileDescriptor())) {
                    ByteArrayOutputStream o = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
                    out = o.toString("UTF-8");
                } finally { pfd.close(); }
            }
        } catch (Throwable ignored) {
        } finally { d1.recycle(); r1.recycle(); }
        int code = -1;
        Parcel d2 = Parcel.obtain(), r2 = Parcel.obtain();
        try {
            d2.writeInterfaceToken(PROCESS);
            proc.transact(P_WAIT_FOR, d2, r2, 0);
            r2.readException();
            code = r2.readInt();
        } catch (Throwable ignored) {
        } finally { d2.recycle(); r2.recycle(); }
        return new Shell.Result(code, out);
    }

    /** Starts {@code sh -c script} and returns its stdout as a stream (closing it ends the process), or null. */
    static java.io.InputStream openStream(String script) {
        IBinder b = binder;
        if (b == null || !granted()) return null;
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        final IBinder proc;
        try {
            data.writeInterfaceToken(SERVICE);
            data.writeStringArray(new String[]{"sh", "-c", script});
            data.writeStringArray(null);
            data.writeString(null);
            b.transact(T_NEW_PROCESS, data, reply, 0);
            reply.readException();
            proc = reply.readStrongBinder();
        } catch (Throwable t) {
            return null;
        } finally { data.recycle(); reply.recycle(); }
        if (proc == null) return null;
        Parcel d1 = Parcel.obtain(), r1 = Parcel.obtain();
        try {
            d1.writeInterfaceToken(PROCESS);
            proc.transact(P_GET_INPUT, d1, r1, 0);
            r1.readException();
            if (r1.readInt() == 0) return null;
            final ParcelFileDescriptor pfd = ParcelFileDescriptor.CREATOR.createFromParcel(r1);
            return new ParcelFileDescriptor.AutoCloseInputStream(pfd) {
                @Override public void close() throws java.io.IOException {
                    super.close();
                    Parcel d = Parcel.obtain(), r = Parcel.obtain();
                    try { // reap the process
                        d.writeInterfaceToken(PROCESS);
                        proc.transact(6 /* destroy */, d, r, 0);
                    } catch (Throwable ignored) {
                    } finally { d.recycle(); r.recycle(); }
                }
            };
        } catch (Throwable t) {
            return null;
        } finally { d1.recycle(); r1.recycle(); }
    }

    /** Shizuku delivers its binder here when it starts, and whenever Grove Guard starts. */
    public static final class Provider extends ContentProvider {
        @Override public boolean onCreate() { return true; }

        @Override public Bundle call(String method, String arg, Bundle extras) {
            if ("sendBinder".equals(method) && extras != null) {
                try {
                    extras.setClassLoader(moe.shizuku.api.BinderContainer.class.getClassLoader());
                    moe.shizuku.api.BinderContainer bc = extras.getParcelable(EXTRA_BINDER);
                    if (bc != null && getContext() != null) onBinder(bc.binder, getContext().getPackageName());
                } catch (Throwable ignored) { }
            }
            return new Bundle();
        }

        @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) { return null; }
        @Override public String getType(Uri u) { return null; }
        @Override public Uri insert(Uri u, ContentValues v) { return null; }
        @Override public int delete(Uri u, String s, String[] a) { return 0; }
        @Override public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
    }
}
