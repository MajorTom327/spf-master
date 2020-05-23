#!/bin/bash
curl -X POST \
     -F token=e706f2de309d31d6e77983be2327fc \
     -F ref=master \
     https://gitlab.styx-sys.com/api/v4/projects/132/trigger/pipeline
