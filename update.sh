#!/bin/bash
# Set the project path as an environment variable 
cd ${GH_PROJ_PATH}
git pull 
docker build -f Dockerfile 
