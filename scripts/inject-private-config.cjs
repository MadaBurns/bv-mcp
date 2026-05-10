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
    
    fs.writeFileSync('wrangler.production.jsonc', JSON.stringify(publicConfig, null, 2));
    console.log("Successfully generated wrangler.production.jsonc with injected private configuration.");
}

inject();
