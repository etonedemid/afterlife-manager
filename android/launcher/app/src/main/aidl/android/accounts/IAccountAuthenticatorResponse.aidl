package android.accounts;

import android.os.Bundle;

// Compile-time copy of the framework interface: the boot class path wins at runtime, so
// AccountManagerHook's subclass of Stub extends the real framework class.
oneway interface IAccountAuthenticatorResponse {
    void onResult(in Bundle value);
    void onRequestContinued();
    void onError(int errorCode, String errorMessage);
}
