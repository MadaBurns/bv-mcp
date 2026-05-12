const fs = require('fs');

const path = '.dev/wrangler.deploy.jsonc';
const config = JSON.parse(fs.readFileSync(path, 'utf8'));

if (!config.queues.consumers) {
    config.queues.consumers = [
        {
            "queue": "bv-scanner-queue",
            "max_batch_size": 100,
            "max_batch_timeout": 5,
            "max_retries": 3
        }
    ];
}

fs.writeFileSync(path, JSON.stringify(config, null, 2));
