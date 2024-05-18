#!/bin/bash

echo "$(cat $1.sha256)" $1 | sha256sum --check
