package com.zettabridge.launcher;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.AuthenticatorDescription;
import android.accounts.IAccountAuthenticatorResponse;
import android.app.Service;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.content.res.XmlResourceParser;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.util.AtomicFile;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Account manager virtualization. A plugin's account authenticator is not registered with the
 * system (nothing is installed), so the system cannot bind it and addAccount fails. Plugin
 * contexts get an AccountManager whose IAccountManager answers the plugin's own account types
 * here: accounts live in <plugin data>/accounts.json, and the calls the system would forward to
 * the authenticator (addAccount, getAuthToken, ...) run the plugin's authenticator service
 * in-process on a worker thread, like the binder thread they run on normally. Other account
 * types go to the real service.
 */
final class AccountManagerHook implements InvocationHandler {
    private static final String TAG = "zb-launcher";
    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";
    private static final Object PASS = new Object();

    private final Object real;
    private final LoadedPlugin plugin;
    private final Map<String, ServiceInfo> authenticators;
    private final Map<String, AuthenticatorDescription> descriptions;
    private final Map<String, AbstractAccountAuthenticator> started = new HashMap<>();
    private final AtomicFile file;
    private final Handler worker;
    private JSONObject store;

    private AccountManagerHook(Object real, LoadedPlugin plugin, Map<String, ServiceInfo> authenticators,
                               Map<String, AuthenticatorDescription> descriptions) {
        this.real = real;
        this.plugin = plugin;
        this.authenticators = authenticators;
        this.descriptions = descriptions;
        this.file = new AtomicFile(new File(plugin.record.dataDir(), "accounts.json"));
        // A looper thread: authenticator services commonly create a Handler in onCreate.
        HandlerThread thread = new HandlerThread("zb-accounts");
        thread.start();
        this.worker = new Handler(thread.getLooper());
    }

    /** The AccountManager for plugin contexts; the real one when the plugin has no authenticator. */
    static AccountManager wrap(Context context, LoadedPlugin plugin, AccountManager realManager) {
        Map<String, ServiceInfo> authenticators = new HashMap<>();
        Map<String, AuthenticatorDescription> descriptions = new HashMap<>();
        for (ServiceInfo s : plugin.services.values()) {
            if (s.metaData == null) continue;
            int xml = s.metaData.getInt(AccountManager.AUTHENTICATOR_META_DATA_NAME);
            if (xml != 0) parseAuthenticator(plugin, s, xml, authenticators, descriptions);
        }
        if (authenticators.isEmpty() || realManager == null) return realManager;
        try {
            Class<?> iam = Class.forName("android.accounts.IAccountManager");
            Object realService = Reflect.field(AccountManager.class, "mService").get(realManager);
            Object proxy = Proxy.newProxyInstance(iam.getClassLoader(), new Class<?>[] {iam},
                    new AccountManagerHook(realService, plugin, authenticators, descriptions));
            AccountManager am = (AccountManager) AccountManager.class.getDeclaredConstructor(Context.class, iam)
                    .newInstance(context, proxy);
            disableCaches(am);
            Log.i(TAG, "plugin " + plugin.packageName + ": account types " + authenticators.keySet());
            return am;
        } catch (ReflectiveOperationException | RuntimeException e) {
            Log.w(TAG, "cannot virtualize the account manager", e);
            return realManager;
        }
    }

    private static void parseAuthenticator(LoadedPlugin plugin, ServiceInfo s, int xml,
                                           Map<String, ServiceInfo> authenticators,
                                           Map<String, AuthenticatorDescription> descriptions) {
        try (XmlResourceParser parser = plugin.resources.getXml(xml)) {
            int event;
            while ((event = parser.next()) != XmlPullParser.END_DOCUMENT && event != XmlPullParser.START_TAG) {
                // skip to the root element
            }
            if (event != XmlPullParser.START_TAG || !"account-authenticator".equals(parser.getName())) return;
            int typeRes = parser.getAttributeResourceValue(ANDROID_NS, "accountType", 0);
            String type = typeRes != 0 ? plugin.resources.getString(typeRes)
                    : parser.getAttributeValue(ANDROID_NS, "accountType");
            if (type == null) return;
            authenticators.put(type, s);
            descriptions.put(type, new AuthenticatorDescription(type, plugin.packageName,
                    parser.getAttributeResourceValue(ANDROID_NS, "label", 0),
                    parser.getAttributeResourceValue(ANDROID_NS, "icon", 0),
                    parser.getAttributeResourceValue(ANDROID_NS, "smallIcon", 0),
                    parser.getAttributeResourceValue(ANDROID_NS, "accountPreferences", 0)));
        } catch (Exception e) {
            Log.w(TAG, "cannot read the account authenticator of " + s.name + ": " + e);
        }
    }

    /** Android 14+ caches accounts and user data until the system bumps a nonce; ours never does. */
    private static void disableCaches(AccountManager am) {
        try {
            Class<?> cache = Class.forName("android.app.PropertyInvalidatedCache");
            for (Field f : AccountManager.class.getDeclaredFields()) {
                f.setAccessible(true);
                Object value = f.get(am);
                if (cache.isInstance(value)) Reflect.method(cache, "disableLocal").invoke(value);
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // no caches on this Android version
        }
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        Object[] a = args != null ? args : new Object[0];
        Object local = local(method.getName(), a);
        if (local != PASS) return local;
        try {
            Object result = method.invoke(real, args);
            return merged(method.getName(), a, result);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private boolean ours(String type) {
        return type != null && authenticators.containsKey(type);
    }

    private static Account account(Object[] args) {
        for (Object o : args) if (o instanceof Account) return (Account) o;
        return null;
    }

    /** The answer for a plugin account type, or PASS for the real service. */
    private Object local(String name, Object[] args) {
        switch (name) {
            case "getAccounts":
            case "getAccountsAsUser":
            case "getAccountsByTypeForPackage":
                return ours((String) args[0]) ? accounts((String) args[0]) : PASS;
            case "getAccountsAndVisibilityForPackage": {
                String type = (String) args[1];
                if (!ours(type)) return PASS;
                Map<Account, Integer> map = new HashMap<>();
                for (Account acc : accounts(type)) map.put(acc, AccountManager.VISIBILITY_VISIBLE);
                return map;
            }
            case "getAccountsByFeatures":
            case "getAccountByTypeAndFeatures": {
                String type = (String) args[1];
                if (!ours(type)) return PASS;
                // ponytail: features are not checked; ask the authenticator's hasFeatures if an app needs it.
                Account[] list = accounts(type);
                Bundle b = new Bundle();
                if (name.equals("getAccountsByFeatures")) {
                    b.putParcelableArray(AccountManager.KEY_ACCOUNTS, list);
                } else if (list.length > 0) {
                    b.putString(AccountManager.KEY_ACCOUNT_NAME, list[0].name);
                    b.putString(AccountManager.KEY_ACCOUNT_TYPE, list[0].type);
                }
                reply(args[0], b);
                return null;
            }
            case "addAccount":
            case "addAccountAsUser": {
                String type = (String) args[1];
                if (!ours(type)) return PASS;
                String tokenType = (String) args[2];
                String[] features = (String[]) args[3];
                Bundle options = (Bundle) args[5];
                run(args[0], type, null, (auth, r) -> auth.addAccount(r, type, tokenType, features, options));
                return null;
            }
            case "editProperties": {
                String type = (String) args[1];
                if (!ours(type)) return PASS;
                run(args[0], type, null, (auth, r) -> auth.editProperties(r, type));
                return null;
            }
            case "invalidateAuthToken":
                if (!ours((String) args[0])) return PASS;
                invalidate((String) args[0], (String) args[1]);
                return null;
            default:
                break;
        }

        Account acc = account(args);
        if (acc == null || !ours(acc.type)) return PASS;
        switch (name) {
            case "getPassword":
                return get(acc, null, "password");
            case "getUserData":
                return get(acc, "data", (String) args[1]);
            case "peekAuthToken":
                return get(acc, "tokens", (String) args[1]);
            case "setPassword":
                put(acc, null, "password", (String) args[1]);
                return null;
            case "clearPassword":
                put(acc, null, "password", null);
                return null;
            case "setUserData":
                put(acc, "data", (String) args[1], (String) args[2]);
                return null;
            case "setAuthToken":
                put(acc, "tokens", (String) args[1], (String) args[2]);
                return null;
            case "addAccountExplicitly":
            case "addAccountExplicitlyWithVisibility":
                return add(acc, (String) args[1], (Bundle) args[2]);
            case "removeAccountExplicitly":
                return remove(acc);
            case "removeAccount":
            case "removeAccountAsUser": {
                // ponytail: removal is always allowed; ask getAccountRemovalAllowed if an app vetoes it.
                remove(acc);
                Bundle b = new Bundle();
                b.putBoolean(AccountManager.KEY_BOOLEAN_RESULT, true);
                reply(args[0], b);
                return null;
            }
            case "hasFeatures": {
                Bundle b = new Bundle();
                b.putBoolean(AccountManager.KEY_BOOLEAN_RESULT, true);
                reply(args[0], b);
                return null;
            }
            case "getAuthToken": {
                String tokenType = (String) args[2];
                Bundle options = (Bundle) args[5];
                String cached = get(acc, "tokens", tokenType);
                if (cached != null) {
                    Bundle b = new Bundle();
                    b.putString(AccountManager.KEY_ACCOUNT_NAME, acc.name);
                    b.putString(AccountManager.KEY_ACCOUNT_TYPE, acc.type);
                    b.putString(AccountManager.KEY_AUTHTOKEN, cached);
                    reply(args[0], b);
                } else {
                    run(args[0], acc.type, tokenType, (auth, r) -> auth.getAuthToken(r, acc, tokenType, options));
                }
                return null;
            }
            case "updateCredentials": {
                String tokenType = (String) args[2];
                Bundle options = (Bundle) args[4];
                run(args[0], acc.type, tokenType, (auth, r) -> auth.updateCredentials(r, acc, tokenType, options));
                return null;
            }
            case "confirmCredentialsAsUser": {
                Bundle options = (Bundle) args[2];
                run(args[0], acc.type, null, (auth, r) -> auth.confirmCredentials(r, acc, options));
                return null;
            }
            case "accountAuthenticated":
            case "setAccountVisibility":
                return true;
            case "getAccountVisibility":
                return AccountManager.VISIBILITY_VISIBLE;
            case "getPackagesAndVisibilityForAccount":
                return new HashMap<String, Integer>();
            case "getPreviousName":
                return null;
            default:
                return PASS;
        }
    }

    /** Queries that span every account type also list the plugin's accounts. */
    private Object merged(String name, Object[] args, Object result) {
        switch (name) {
            case "getAccounts":
            case "getAccountsAsUser":
            case "getAccountsByTypeForPackage":
                if (args[0] != null) return result;
                // fall through: a null type means all types
            case "getAccountsForPackage": {
                List<Account> all = new ArrayList<>(Arrays.asList(accounts(null)));
                if (result != null) all.addAll(Arrays.asList((Account[]) result));
                return all.toArray(new Account[0]);
            }
            case "getAuthenticatorTypes": {
                List<AuthenticatorDescription> all = new ArrayList<>(descriptions.values());
                if (result != null) all.addAll(Arrays.asList((AuthenticatorDescription[]) result));
                return all.toArray(new AuthenticatorDescription[0]);
            }
            default:
                return result;
        }
    }

    // The plugin's authenticator.

    private interface AuthCall {
        Bundle run(AbstractAccountAuthenticator auth, AccountAuthenticatorResponse response) throws Exception;
    }

    private void run(Object response, String type, String tokenType, AuthCall call) {
        worker.post(() -> {
            Session session = new Session(response, tokenType);
            try {
                AccountAuthenticatorResponse r = AccountAuthenticatorResponse.class
                        .getConstructor(IAccountAuthenticatorResponse.class).newInstance(session);
                Bundle result = call.run(authenticator(type), r);
                if (result != null) session.onResult(result);
            } catch (Throwable t) {
                if (t instanceof InvocationTargetException) t = t.getCause();
                Log.w(TAG, "plugin account authenticator for " + type + " failed", t);
                fail(response, AccountManager.ERROR_CODE_REMOTE_EXCEPTION, String.valueOf(t));
            }
        });
    }

    /** Starts the authenticator service in-process, as the system would on bind, and returns its authenticator. */
    private synchronized AbstractAccountAuthenticator authenticator(String type) throws Exception {
        AbstractAccountAuthenticator auth = started.get(type);
        if (auth != null) return auth;
        ServiceInfo info = authenticators.get(type);
        Service service = (Service) plugin.classLoader.loadClass(info.name).getDeclaredConstructor().newInstance();
        Reflect.method(ContextWrapper.class, "attachBaseContext", Context.class)
                .invoke(service, plugin.application.getBaseContext());
        Reflect.trySet(Service.class, service, "mApplication", plugin.application);
        service.onCreate();
        IBinder binder = service.onBind(new Intent(AccountManager.ACTION_AUTHENTICATOR_INTENT)
                .setClassName(plugin.packageName, info.name));
        // AbstractAccountAuthenticator.Transport checks the ACCOUNT_MANAGER permission (system only),
        // so call the authenticator itself, the Transport's outer instance.
        Object outer = binder != null ? Reflect.field(binder.getClass(), "this$0").get(binder) : null;
        if (!(outer instanceof AbstractAccountAuthenticator)) {
            throw new IllegalStateException(info.name + " did not return an AbstractAccountAuthenticator binder");
        }
        auth = (AbstractAccountAuthenticator) outer;
        started.put(type, auth);
        return auth;
    }

    /** Stands in for the system's session: forwards the authenticator's answer to the AccountManager caller. */
    private final class Session extends IAccountAuthenticatorResponse.Stub {
        private final Object response;
        private final String tokenType;

        Session(Object response, String tokenType) {
            this.response = response;
            this.tokenType = tokenType;
        }

        @Override
        public void onResult(Bundle value) {
            if (value != null && tokenType != null) {
                String name = value.getString(AccountManager.KEY_ACCOUNT_NAME);
                String type = value.getString(AccountManager.KEY_ACCOUNT_TYPE);
                String token = value.getString(AccountManager.KEY_AUTHTOKEN);
                if (name != null && type != null && token != null) {
                    put(new Account(name, type), "tokens", tokenType, token);
                }
            }
            reply(response, value);
        }

        @Override
        public void onRequestContinued() {}

        @Override
        public void onError(int errorCode, String errorMessage) {
            fail(response, errorCode, errorMessage);
        }
    }

    /** IAccountManagerResponse.onResult on the caller's response binder (local to this process). */
    private static void reply(Object response, Bundle value) {
        callResponse(response, "onResult", new Class<?>[] {Bundle.class}, value);
    }

    private static void fail(Object response, int code, String message) {
        callResponse(response, "onError", new Class<?>[] {int.class, String.class}, code, message);
    }

    private static void callResponse(Object response, String name, Class<?>[] types, Object... args) {
        if (response == null) return;
        try {
            Class.forName("android.accounts.IAccountManagerResponse").getMethod(name, types).invoke(response, args);
        } catch (ReflectiveOperationException | RuntimeException e) {
            Log.w(TAG, "cannot answer an account manager call: " + e);
        }
    }

    // Account store: {"<type>\n<name>": {"name", "type", "password", "data": {}, "tokens": {}}}.

    private JSONObject store() {
        if (store == null) {
            try {
                store = new JSONObject(new String(file.readFully(), StandardCharsets.UTF_8));
            } catch (IOException | JSONException e) {
                store = new JSONObject();
            }
        }
        return store;
    }

    private void save() {
        FileOutputStream out = null;
        try {
            out = file.startWrite();
            out.write(store().toString().getBytes(StandardCharsets.UTF_8));
            file.finishWrite(out);
        } catch (IOException e) {
            if (out != null) file.failWrite(out);
            Log.w(TAG, "cannot save plugin accounts: " + e);
        }
    }

    private static String key(Account a) {
        return a.type + "\n" + a.name;
    }

    private synchronized Account[] accounts(String type) {
        List<Account> list = new ArrayList<>();
        for (Iterator<String> it = store().keys(); it.hasNext(); ) {
            JSONObject e = store().optJSONObject(it.next());
            if (e != null && (type == null || type.equals(e.optString("type")))) {
                list.add(new Account(e.optString("name"), e.optString("type")));
            }
        }
        return list.toArray(new Account[0]);
    }

    private synchronized boolean add(Account a, String password, Bundle extras) {
        if (store().has(key(a))) return false;
        try {
            JSONObject e = new JSONObject().put("name", a.name).put("type", a.type);
            if (password != null) e.put("password", password);
            JSONObject data = new JSONObject();
            if (extras != null) for (String k : extras.keySet()) data.put(k, String.valueOf(extras.get(k)));
            e.put("data", data).put("tokens", new JSONObject());
            store().put(key(a), e);
        } catch (JSONException e) {
            return false;
        }
        save();
        return true;
    }

    private synchronized boolean remove(Account a) {
        if (store().remove(key(a)) == null) return false;
        save();
        return true;
    }

    /** section null addresses the entry itself (the password). */
    private synchronized String get(Account a, String section, String k) {
        JSONObject e = store().optJSONObject(key(a));
        if (e != null && section != null) e = e.optJSONObject(section);
        return e != null && k != null && e.has(k) ? e.optString(k) : null;
    }

    private synchronized void put(Account a, String section, String k, String value) {
        JSONObject e = store().optJSONObject(key(a));
        if (e == null || k == null) return;
        try {
            if (section != null) {
                JSONObject s = e.optJSONObject(section);
                if (s == null) e.put(section, s = new JSONObject());
                e = s;
            }
            if (value == null) e.remove(k);
            else e.put(k, value);
        } catch (JSONException ignored) {
            return;
        }
        save();
    }

    private synchronized void invalidate(String type, String token) {
        boolean changed = false;
        for (Iterator<String> it = store().keys(); it.hasNext(); ) {
            JSONObject e = store().optJSONObject(it.next());
            if (e == null || !type.equals(e.optString("type"))) continue;
            JSONObject tokens = e.optJSONObject("tokens");
            if (tokens == null) continue;
            List<String> stale = new ArrayList<>();
            for (Iterator<String> t = tokens.keys(); t.hasNext(); ) {
                String k = t.next();
                if (token != null && token.equals(tokens.optString(k))) stale.add(k);
            }
            for (String k : stale) tokens.remove(k);
            changed |= !stale.isEmpty();
        }
        if (changed) save();
    }
}
