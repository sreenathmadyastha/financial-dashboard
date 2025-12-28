import React from 'react';
import { useConfig } from './hooks/useConfig';

function App() {
    const { config, loading, error } = useConfig();

    if (loading) return <div>Loading config...</div>;
    if (error) return <div>Error: {error}</div>;  // Or fallback defaults

    return (
        <div className={`app ${config?.theme || 'default'}`}>
            {config?.enableFeatureX && <div>Feature X Enabled!</div>}
            {/* Rest of your app */}
        </div>
    );
}

export default App;