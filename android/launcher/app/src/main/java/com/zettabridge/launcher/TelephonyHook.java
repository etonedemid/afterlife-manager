package com.zettabridge.launcher;

import android.content.Context;
import android.os.IBinder;
import android.provider.Settings;
import android.util.Log;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

/**
 * Device identifiers for old apps. Since Android 10 a normal app asking for the IMEI, IMSI, SIM
 * serial or phone number gets a SecurityException; old apps (ChatOn registration) expect the
 * value and crash. The phone services are swapped in ServiceManager's cache for proxies that
 * answer a refused identifier instead: a stable fake IMEI for device id queries, null (no SIM)
 * for the rest.
 */
final class TelephonyHook implements InvocationHandler {
    private static final String TAG = "zb-launcher";

    private final Object real;
    private final String imei;
    private IBinder binder;

    private TelephonyHook(Object real, String imei) {
        this.real = real;
        this.imei = imei;
    }

    static void install(Context host) {
        String imei = fakeImei(Settings.Secure.getString(host.getContentResolver(), Settings.Secure.ANDROID_ID));
        hook("phone", "com.android.internal.telephony.ITelephony", imei);
        hook("iphonesubinfo", "com.android.internal.telephony.IPhoneSubInfo", imei);
    }

    @SuppressWarnings("unchecked")
    private static void hook(String service, String interfaceName, String imei) {
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            IBinder realBinder = (IBinder) Reflect.method(sm, "getService", String.class).invoke(null, service);
            if (realBinder == null || Proxy.isProxyClass(realBinder.getClass())) return;
            Class<?> iface = Class.forName(interfaceName);
            Object realService = Reflect.method(Class.forName(interfaceName + "$Stub"), "asInterface", IBinder.class)
                    .invoke(null, realBinder);
            TelephonyHook hook = new TelephonyHook(realService, imei);
            Object service2 = Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[] {iface}, hook);
            // Stub.asInterface asks the binder for a local interface first: hand it the proxy.
            hook.binder = (IBinder) Proxy.newProxyInstance(IBinder.class.getClassLoader(), new Class<?>[] {IBinder.class},
                    (p, m, a) -> "queryLocalInterface".equals(m.getName()) ? service2 : invokeOn(realBinder, m, a));
            ((Map<String, IBinder>) Reflect.field(sm, "sCache").get(null)).put(service, hook.binder);
        } catch (ReflectiveOperationException | RuntimeException e) {
            Log.w(TAG, "cannot hook the " + service + " service: " + e);
        }
    }

    private static Object invokeOn(Object target, Method m, Object[] args) throws Throwable {
        try {
            return m.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if ("asBinder".equals(method.getName())) return binder;
        try {
            return method.invoke(real, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (!(cause instanceof SecurityException) || method.getReturnType() != String.class) throw cause;
            String name = method.getName();
            return name.contains("DeviceId") || name.contains("Imei") ? imei : null;
        }
    }

    /** 15 digits with a valid Luhn check digit, stable per device (ANDROID_ID). */
    static String fakeImei(String seed) {
        long h = (seed != null ? seed : "afterlife").hashCode() & 0xffffffffL;
        StringBuilder sb = new StringBuilder("35");
        sb.append(String.format(java.util.Locale.ROOT, "%012d", h % 1_000_000_000_000L));
        int sum = 0;
        for (int i = 0; i < 14; i++) {
            int d = sb.charAt(i) - '0';
            if (i % 2 == 1) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
        }
        return sb.append((10 - sum % 10) % 10).toString();
    }
}
