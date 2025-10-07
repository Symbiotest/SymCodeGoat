// vulnerable_uri.cpp
// Purpose: Minimal example that includes username:password directly in a URI
// This is intentionally insecure and should only be used for testing scanners.

#include <iostream>
#include <string>

int main() {
    // Insecure: Username and password embedded directly in the URI
    // Matches pattern: http://Alice01:Passw0rd!@internal.example.com/login
    std::string serviceUrl = "http://Alice01:Passw0rd!@internal.example.com/login";

    // Simulate using the URL (printing/logging it — another leak vector)
    std::cout << "Connecting to: " << serviceUrl << std::endl;

    // Further "use" of the URL (for demonstration only)
    // In a real program this might be passed to an HTTP client library,
    // causing credentials to appear in logs or network captures.
    if (serviceUrl.find("http://") == 0) {
        std::cout << "Protocol appears to be HTTP; credentials are embedded in the URI." << std::endl;
    }

    return 0;
}