# W6 fixture recorder

This offline-only utility sanitizes an owner-exported HAR/HTTP trace into a compatibility fixture. Export the HAR from the router administration UI or browser developer tools without sending it anywhere. The export may contain credentials and other secrets; treat it as sensitive until sanitization. Run with `--owner-authorized-home-router`; the tool never captures traffic or makes router requests.
