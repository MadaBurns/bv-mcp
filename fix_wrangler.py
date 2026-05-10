import re

def fix(path):
    with open(path, 'r') as f:
        content = f.read()
    
    # Remove all comments
    content = re.sub(r'//.*', '', content)
    
    # Now parse JSON. Note: This will be a bit brittle but should work for this structure.
    import json
    # Use a relaxed parser or just fix the manual editing
    # Actually, the file uses // comments which is invalid JSON.
    # The wrangler tool handles it, but JSON.parse() doesn't.
    # I will replace the known comment lines manually before parsing.
    
    # Use a regex that replaces // comments with empty lines
    clean = re.sub(r'//.*', '', content)
    
    config = json.loads(clean)
    
    if 'services' not in config:
        config['services'] = []
    
    if not any(s['binding'] == 'BV_WEB' for s in config['services']):
        config['services'].append({"binding": "BV_WEB", "service": "blackveil-web"})
        
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)

fix('wrangler.jsonc')
fix('.dev/wrangler.deploy.jsonc')
