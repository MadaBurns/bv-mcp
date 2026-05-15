const fs = require('fs');
const path = require('path');

/**
 * Automates the "Private Injection" process.
 * Merges the public engine build with local private overrides.
 */
function inject() {
    const publicConfig = JSON.parse(fs.readFileSync('wrangler.jsonc', 'utf8'));
    const privateConfigPath = '.dev/wrangler.deploy.jsonc';
    
    if (!fs.existsSync(privateConfigPath)) {
        console.error("Missing .dev/wrangler.deploy.jsonc - skipping injection.");
        return;
    }
    
    const privateConfig = JSON.parse(fs.readFileSync(privateConfigPath, 'utf8'));
    
    // Merge Strategy: Private config bindings override public defaults
    publicConfig.services = privateConfig.services;
    publicConfig.vars = { ...publicConfig.vars, ...privateConfig.vars };
    if (privateConfig.queues) {
        publicConfig.queues = privateConfig.queues;
    }
    
    // Core Infrastructure: KV, D1, Analytics
    if (privateConfig.kv_namespaces) {
        publicConfig.kv_namespaces = privateConfig.kv_namespaces;
    }
    if (privateConfig.d1_databases) {
        publicConfig.d1_databases = privateConfig.d1_databases;
    }
    if (privateConfig.analytics_engine_datasets) {
        publicConfig.analytics_engine_datasets = privateConfig.analytics_engine_datasets;
    }
    if (privateConfig.r2_buckets) {
        publicConfig.r2_buckets = privateConfig.r2_buckets;
    }
    
    fs.writeFileSync('wrangler.production.jsonc', JSON.stringify(publicConfig, null, 2));
    console.log("Successfully generated wrangler.production.jsonc with injected private configuration.");
}

inject();
