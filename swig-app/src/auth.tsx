import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Loader2 } from 'lucide-react';

type AuthenticationState = {
  authenticated: boolean;
  publicKey: string | null;
  username: string | null;
};

const PasskeySolanaAuth = () => {
  const [authState, setAuthState] = useState<AuthenticationState>({
    authenticated: false,
    publicKey: null,
    username: null,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasPasskey, setHasPasskey] = useState<boolean | null>(null);

  // Check for existing passkeys on component mount
  useEffect(() => {
    checkExistingPasskey();
  }, []);

  const checkExistingPasskey = async () => {
    try {
      if (!isPasskeySupported()) {
        setHasPasskey(false);
        return;
      }
      const d= await PublicKeyCredential.isConditionalMediationAvailable();
      console.log(d);

      const creds = await navigator.credentials.get({
        mediation: "required",
        publicKey: {
          challenge: new Uint8Array(32),
          rpId: window.location.hostname,
          userVerification: "discouraged",
        }
      });
      console.log(creds);
      setHasPasskey(!!creds);
      return !!creds;
    } catch (err) {
      // If we get a specific "no credentials" error, that's fine
      // Otherwise log the error but assume no credentials
      if (err instanceof DOMException && err.name === 'NotAllowedError') {
        setHasPasskey(false);
      } else {
        console.error('Error checking for passkey:', err);
        setHasPasskey(false);
      }
      setLoading(false);
      return false;
    }
  };

  const isPasskeySupported = () => {
    return window.PublicKeyCredential &&
      typeof window.PublicKeyCredential === 'function' &&
      typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
  };

  const registerPasskey = async (username: string) => {
    checkExistingPasskey();
    if (hasPasskey) {
      return;
    }
    try {
      setLoading(true);
      setError(null);

      // Check for existing passkey first
      const hasExisting = await checkExistingPasskey();
      if (hasExisting) {
        setError('You already have a passkey for this site. Please sign in instead.');
        return;
      }

      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const createCredentialOptions = {
        challenge,
        rp: {
          id: window.location.hostname,
        },
        user: {
          id: new Uint8Array(16),
          name: username,
          displayName: username,
        },
        pubKeyCredParams: [{
          type: 'public-key',
          alg: -7 // ES256
        }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          requireResidentKey: true,
          userVerification: 'required'
        },
        extensions: {
          credProps: true
        }
      };

      const credential = await navigator.credentials.create({
        publicKey: createCredentialOptions
      }) as PublicKeyCredential;

      setAuthState({
        authenticated: true,
        publicKey: credential.id,
        username
      });

      setHasPasskey(true);
      return credential;
    } catch (err) {
      setError('Failed to create passkey: ' + (err as Error).message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const signInWithPasskey = async () => {
    try {
      setLoading(true);
      setError(null);

      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const credential = await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId: window.location.hostname,
          userVerification: 'required',
        }
      }) as PublicKeyCredential;

      setAuthState({
        authenticated: true,
        publicKey: credential.id,
        username: 'User' // In production, get from server
      });

      return credential;
    } catch (err) {
      setError('Failed to sign in with passkey: ' + (err as Error).message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  // ... rest of the code (signTransaction function) remains the same ...

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-100 p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Passkey Solana Auth</CardTitle>
        </CardHeader>
        <CardContent>
          {error && (
            <span className="text-red-500">{error}</span>
          )}

          {!authState.authenticated ? (
            <div className="space-y-4">
              { hasPasskey ? (
                <Button 
                  className="w-full"
                  onClick={signInWithPasskey}
                  disabled={loading || !isPasskeySupported()}
                >
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Sign In with Passkey
                </Button>
              ) : (
                <Button 
                  className="w-full"
                  onClick={() => registerPasskey('user@example.com')}
                  disabled={loading || !isPasskeySupported()}
                >
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Create New Passkey
                </Button>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-gray-500">
                Signed in as {authState.username}
              </p>
              <Button 
                className="w-full"
                
                disabled={loading}
              >
                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Sign Solana Transaction
              </Button>
            </div>
          )}
        </CardContent>
        <CardFooter className="text-sm text-gray-500">
          {!isPasskeySupported() && (
            <p>Passkeys are not supported in your browser.</p>
          )}
        </CardFooter>
      </Card>
    </div>
  );
};

export default PasskeySolanaAuth;