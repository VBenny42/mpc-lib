#!/bin/sh

chmod -R 777 . 2> /dev/null
docker compose up -d
docker compose exec mpc bash
