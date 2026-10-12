#!/bin/sh
curl -s "$STORE/features" | python3 -c "import json,sys; print(json.load(sys.stdin))"
