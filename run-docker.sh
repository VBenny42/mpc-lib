#!/bin/sh

chmod -R 777 .
docker compose up -d
docker compose exec mpc bash
