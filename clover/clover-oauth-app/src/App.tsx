import React, { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle, Key, Server } from 'lucide-react';

// Clover OAuth Configuration
const CLOVER_CONFIG = {
  clientId: 'KEC9W43YQJGQY', // Replace with your Clover App ID
  redirectUri: 'http://localhost:5173/callback', // Vite default port
  authUrl: 'https://sandbox.dev.clover.com/oauth/authorize',
  tokenUrl: 'https://sandbox.dev.clover.com/oauth/token',
  apiBaseUrl: 'https://sandbox.dev.clover.com/v3'
};

interface TokenResponse {
  access_token: string;
  merchant_id?: string;
}

interface MerchantInfo {
  id: string;
  name: string;
  address?: {
    address1?: string;
    city?: string;
    state?: string;
  };
}

export default function CloverOAuthApp() {
  const [step, setStep] = useState<'initial' | 'authorizing' | 'exchanging' | 'success' | 'error'>('initial');
  const [accessToken, setAccessToken] = useState<string>('');
  const [merchantId, setMerchantId] = useState<string>('');
  const [merchantInfo, setMerchantInfo] = useState<MerchantInfo | null>(null);
  const [error, setError] = useState<string>('');
  const [clientSecret, setClientSecret] = useState<string>('');

  useEffect(() => {
    // Check if we're on the callback URL
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const merchantIdParam = urlParams.get('merchant_id');
    const errorParam = urlParams.get('error');

    if (errorParam) {
      setError(`Authorization error: ${errorParam}`);
      setStep('error');
      return;
    }

    if (code && merchantIdParam) {
      setMerchantId(merchantIdParam);
      setStep('exchanging');

      // In a real app, this should be done on your backend
      // We'll simulate the token exchange here
      exchangeCodeForToken(code, merchantIdParam);
    }
  }, []);

  const startOAuthFlow = () => {
    if (!clientSecret) {
      setError('Please enter your App Secret');
      return;
    }

    setStep('authorizing');

    // Build authorization URL
    const params = new URLSearchParams({
      client_id: CLOVER_CONFIG.clientId,
      redirect_uri: CLOVER_CONFIG.redirectUri
    });

    const authUrl = `${CLOVER_CONFIG.authUrl}?${params.toString()}`;

    // Store client secret in sessionStorage for the callback
    sessionStorage.setItem('clover_client_secret', clientSecret);

    // Redirect to Clover authorization
    window.location.href = authUrl;
  };

  const exchangeCodeForToken = async (code: string, merchantId: string) => {
    try {
      const storedSecret = sessionStorage.getItem('clover_client_secret') || clientSecret;

      // IMPORTANT: In production, this MUST be done on your backend server
      // Exposing client_secret in frontend code is a security risk
      const tokenParams = new URLSearchParams({
        client_id: CLOVER_CONFIG.clientId,
        client_secret: storedSecret,
        code: code
      });

      const response = await fetch(CLOVER_CONFIG.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: tokenParams.toString()
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Token exchange failed: ${errorText}`);
      }

      const data: TokenResponse = await response.json();
      setAccessToken(data.access_token);
      setStep('success');

      // Fetch merchant info
      await fetchMerchantInfo(data.access_token, merchantId);

      // Clean up
      sessionStorage.removeItem('clover_client_secret');

      // Clean URL
      window.history.replaceState({}, document.title, '/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to exchange code for token');
      setStep('error');
    }
  };

  const fetchMerchantInfo = async (token: string, merchantId: string) => {
    try {
      const response = await fetch(
        `${CLOVER_CONFIG.apiBaseUrl}/merchants/${merchantId}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
          }
        }
      );

      if (response.ok) {
        const data: MerchantInfo = await response.json();
        setMerchantInfo(data);
      }
    } catch (err) {
      console.error('Failed to fetch merchant info:', err);
    }
  };

  const reset = () => {
    setStep('initial');
    setAccessToken('');
    setMerchantId('');
    setMerchantInfo(null);
    setError('');
    setClientSecret('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-50 p-8">
      <div className="max-w-2xl mx-auto">
        <div className="bg-white rounded-lg shadow-lg p-8">
          <div className="flex items-center gap-3 mb-6">
            <Server className="w-8 h-8 text-green-600" />
            <h1 className="text-3xl font-bold text-gray-800">Clover OAuth Integration</h1>
          </div>

          {step === 'initial' && (
            <div className="space-y-6">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h3 className="font-semibold text-blue-900 mb-2">Before you start:</h3>
                <ol className="list-decimal list-inside space-y-1 text-sm text-blue-800">
                  <li>Create a Clover developer account at clover.com/developers</li>
                  <li>Create a new app in the Developer Dashboard</li>
                  <li>Set redirect URI to: <code className="bg-white px-2 py-0.5 rounded">http://localhost:5173/callback</code></li>
                  <li>Copy your App ID and App Secret</li>
                  <li>Update CLOVER_CONFIG.clientId in the code with your App ID</li>
                </ol>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  App Secret (Client Secret)
                </label>
                <input
                  type="password"
                  value={clientSecret}
                  onChange={(e) => setClientSecret(e.target.value)}
                  placeholder="Enter your Clover App Secret"
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent"
                />
                <p className="mt-1 text-xs text-gray-500">
                  ⚠️ In production, never expose your secret in frontend code
                </p>
              </div>

              <button
                onClick={startOAuthFlow}
                className="w-full bg-green-600 hover:bg-green-700 text-white font-semibold py-3 px-6 rounded-lg transition duration-200 flex items-center justify-center gap-2"
              >
                <Key className="w-5 h-5" />
                Connect to Clover
              </button>
            </div>
          )}

          {step === 'authorizing' && (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Redirecting to Clover authorization...</p>
            </div>
          )}

          {step === 'exchanging' && (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Exchanging authorization code for access token...</p>
            </div>
          )}

          {step === 'success' && (
            <div className="space-y-6">
              <div className="flex items-center gap-2 text-green-600 bg-green-50 p-4 rounded-lg">
                <CheckCircle className="w-6 h-6" />
                <span className="font-semibold">Successfully connected to Clover!</span>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Access Token
                  </label>
                  <div className="bg-gray-50 p-3 rounded border border-gray-200 break-all text-sm font-mono">
                    {accessToken}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Merchant ID
                  </label>
                  <div className="bg-gray-50 p-3 rounded border border-gray-200 text-sm font-mono">
                    {merchantId}
                  </div>
                </div>

                {merchantInfo && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Merchant Information
                    </label>
                    <div className="bg-gray-50 p-4 rounded border border-gray-200 space-y-2">
                      <p><strong>Name:</strong> {merchantInfo.name}</p>
                      {merchantInfo.address && (
                        <p>
                          <strong>Address:</strong>{' '}
                          {merchantInfo.address.address1}, {merchantInfo.address.city}, {merchantInfo.address.state}
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </div>

              <button
                onClick={reset}
                className="w-full bg-gray-600 hover:bg-gray-700 text-white font-semibold py-3 px-6 rounded-lg transition duration-200"
              >
                Start Over
              </button>
            </div>
          )}

          {step === 'error' && (
            <div className="space-y-6">
              <div className="flex items-start gap-2 text-red-600 bg-red-50 p-4 rounded-lg">
                <AlertCircle className="w-6 h-6 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold">Error occurred</p>
                  <p className="text-sm mt-1">{error}</p>
                </div>
              </div>

              <button
                onClick={reset}
                className="w-full bg-gray-600 hover:bg-gray-700 text-white font-semibold py-3 px-6 rounded-lg transition duration-200"
              >
                Try Again
              </button>
            </div>
          )}
        </div>

        <div className="mt-6 bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h3 className="font-semibold text-yellow-900 mb-2 flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            Security Warning
          </h3>
          <p className="text-sm text-yellow-800">
            This example exposes the client secret in the frontend for demonstration purposes only.
            In a production application, the token exchange MUST be done on your backend server to
            keep your client secret secure.
          </p>
        </div>
      </div>
    </div>
  );
}