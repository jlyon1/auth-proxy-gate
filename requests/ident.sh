#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 token"
  echo "You must provide an auth token on the command line"
  exit 1
fi


curl http://localhost:8081/auth/ident -H "Authorization: $1"