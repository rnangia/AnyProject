#!/usr/bin/env bash

until cd /app && npm install
do
  echo "Retrying npm install"
done

npm run dev
