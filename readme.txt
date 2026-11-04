Cora OS sentinel: complete matching set
========================================
Use the ZIP (cora-os-complete.zip) if you can: it has the right folder structure.
If you download files one by one, put ALL of them in ONE directory, then verify:

    python3 cora_selfcheck.py          # names any stale/missing file and the feature it lacks

Install
    pip install git+https://github.com/nkaralus/engine-telemetry-bus
    pip install llama-cpp-python pytest jsonschema

Verify (root needed for the cgroup / nftables / NFLOG tests; the rest skip themselves)
    sudo -E ./venv/bin/python -m pytest -q -s test_cora_nflog.py
    CORA_GGUF=models/<your-3b>.gguf sudo -E ./venv/bin/python -m pytest -q          # everything

Try it live
    sudo ./venv/bin/python cora_demo.py --model models/<your-3b>.gguf --ephemeral
    sudo ./venv/bin/python cora_demo.py --model models/<your-3b>.gguf --ephemeral --no-nflog   # A/B

Run for real
    sudo ./venv/bin/python cora_sentinel.py --cgroup-root /sys/fs/cgroup/cora --nft --nflog \
        --blocklist ./blocklists --model models/<your-3b>.gguf --enforce
    sudo ./venv/bin/python cora_run.py <task-name> <command...>      # start a task inside the cgroup

Note: test_cora_starter.py needs the cora-security-starter/ folder (it is in the zip);
without it those tests skip rather than fail.
