#!/bin/bash
# VULNERABLE: Using eval with untrusted input from curl

# Insecure: Directly evaluating code from a remote source
function insecure_download_and_run() {
    echo "Downloading and running script..."
    # WARNING: This is extremely dangerous!
    eval "$(curl -s http://example.com/install.sh)"
}

# More secure alternative
function secure_download() {
    local temp_file=$(mktemp)
    
    # Download to a temporary file first
    if curl -s http://example.com/install.sh -o "$temp_file"; then
        # Verify the script's contents before execution
        if grep -q "malicious_pattern" "$temp_file"; then
            echo "Security check failed!" >&2
            rm -f "$temp_file"
            return 1
        fi
        
        # Make executable and run
        chmod +x "$temp_file"
        "$temp_file"
        rm -f "$temp_file"
    else
        echo "Download failed" >&2
        return 1
    fi
}
