const fs = require('fs');

function addBinding(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const config = JSON.parse(content);
    
    if (!config.services) {
        config.services = [];
    }
    
    if (!config.services.find(s => s.binding === 'BV_WEB')) {
        config.services.push({
            "binding": "BV_WEB",
            "service": "bv-web-prod"
        });
    }
    
    fs.writeFileSync(filePath, JSON.stringify(config, null, 2));
}

addBinding('wrangler.jsonc');
addBinding('.dev/wrangler.deploy.jsonc');
